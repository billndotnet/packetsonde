#include "capture_session.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>

#define PS_CAPTURE_DIR_DEFAULT "/var/lib/packetsonde/captures"

/* Session state is small and rarely changes; guard it (and the file write)
 * with a single mutex so set/clear/append are safe under concurrency. */
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static char g_session_id[256];   /* empty string == no active session */

/* Resolve the capture directory: PS_DETECT_CAPTURE_DIR or the default. */
static const char *capture_dir(void)
{
    const char *d = getenv("PS_DETECT_CAPTURE_DIR");
    if (d && d[0]) return d;
    return PS_CAPTURE_DIR_DEFAULT;
}

/* mkdir -p the capture directory (best-effort; ignore EEXIST). Only the final
 * component is created here — the default base (/var/lib/packetsonde) is
 * provisioned at install time and PS_DETECT_CAPTURE_DIR points at an existing
 * tree in tests. */
static void ensure_dir(const char *dir)
{
    if (mkdir(dir, 0755) != 0 && errno != EEXIST) {
        /* Walk and create parents, then retry. */
        char tmp[1024];
        size_t n = strlen(dir);
        if (n >= sizeof tmp) return;
        memcpy(tmp, dir, n + 1);
        for (char *p = tmp + 1; *p; p++) {
            if (*p == '/') {
                *p = '\0';
                mkdir(tmp, 0755);   /* ignore errors */
                *p = '/';
            }
        }
        mkdir(tmp, 0755);           /* ignore errors */
    }
}

void ps_capture_session_set(const char *session_id)
{
    pthread_mutex_lock(&g_lock);
    if (!session_id || !session_id[0]) {
        g_session_id[0] = '\0';
    } else {
        snprintf(g_session_id, sizeof g_session_id, "%s", session_id);
        ensure_dir(capture_dir());
    }
    pthread_mutex_unlock(&g_lock);
}

void ps_capture_session_clear(void)
{
    pthread_mutex_lock(&g_lock);
    g_session_id[0] = '\0';
    pthread_mutex_unlock(&g_lock);
}

int ps_capture_session_append(const char *json_line)
{
    if (!json_line) return 0;

    pthread_mutex_lock(&g_lock);

    if (g_session_id[0] == '\0') {
        pthread_mutex_unlock(&g_lock);
        return 0;   /* no active session — noop */
    }

    char path[1024];
    snprintf(path, sizeof path, "%s/%s.jsonl", capture_dir(), g_session_id);

    FILE *f = fopen(path, "a");
    if (!f) {
        pthread_mutex_unlock(&g_lock);
        return 0;   /* dir missing or unwritable — skip silently */
    }

    size_t len = strlen(json_line);
    fwrite(json_line, 1, len, f);
    /* Ensure exactly one trailing newline. */
    if (len == 0 || json_line[len - 1] != '\n')
        fputc('\n', f);
    fclose(f);

    pthread_mutex_unlock(&g_lock);
    return 1;
}
