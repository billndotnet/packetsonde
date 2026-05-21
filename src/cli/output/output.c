#include "output.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int write_all(int fd, const char *buf, size_t n) {
    while (n > 0) {
        ssize_t w = write(fd, buf, n);
        if (w < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (w == 0) return -1;
        buf += w; n -= (size_t)w;
    }
    return 0;
}

int ps_output_init(struct ps_output *o, const struct ps_output_opts *opts) {
    memset(o, 0, sizeof(*o));
    o->stdout_fd = opts->target_fd ? opts->target_fd : 1;
    o->append_fd = -1;

    int is_tty = opts->assume_tty ? 1 : isatty(o->stdout_fd);

    if (opts->fmt_force) {
        o->fmt = opts->fmt_force;
    } else {
        o->fmt = is_tty ? PS_OFMT_TEXT : PS_OFMT_JSONL;
    }
    o->color = opts->color && (o->fmt == PS_OFMT_TEXT) && is_tty;

    if (getenv("NO_COLOR")) o->color = 0;

    if (opts->auto_append_path && opts->auto_append_path[0]) {
        o->append_fd = open(opts->auto_append_path,
                            O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (o->append_fd < 0) {
            fprintf(stderr, "warning: cannot open %s: %s\n",
                    opts->auto_append_path, strerror(errno));
        }
    }
    pthread_mutex_init(&o->lock, NULL);
    return 0;
}

static int render_text(const struct ps_finding *f, int color, char *buf, size_t sz) {
    return ps_finding_to_text(f, buf, sz, color);
}
static int render_jsonl(const struct ps_finding *f, char *buf, size_t sz) {
    return ps_finding_to_json(f, buf, sz);
}
static int render_quiet(const struct ps_finding *f, char *buf, size_t sz) {
    char target_s[PS_FIND_TARGET_MAX + 32] = "-";
    if (f->target_ip[0] && f->target_port)
        snprintf(target_s, sizeof(target_s), "%s:%u", f->target_ip, f->target_port);
    else if (f->target_hostname[0] && f->target_port)
        snprintf(target_s, sizeof(target_s), "%s:%u", f->target_hostname, f->target_port);
    else if (f->target_ip[0])
        snprintf(target_s, sizeof(target_s), "%s", f->target_ip);
    else if (f->target_hostname[0])
        snprintf(target_s, sizeof(target_s), "%s", f->target_hostname);
    int n = snprintf(buf, sz, "%s\t%s\t%s\t%s\n",
                     ps_severity_str(f->severity), f->kind, target_s, f->title);
    return (n < 0 || (size_t)n >= sz) ? -1 : n;
}

void ps_output_emit(struct ps_output *o, const struct ps_finding *f) {
    char text_buf [PS_FIND_TITLE_MAX + PS_FIND_TARGET_MAX + 256];
    char jsonl_buf[PS_FIND_EVIDENCE_MAX + 2048];

    int tn = -1;
    int jn = -1;

    int need_jsonl = (o->append_fd >= 0) ||
                     (o->fmt == PS_OFMT_JSON || o->fmt == PS_OFMT_JSONL);
    int need_text  = (o->fmt == PS_OFMT_TEXT  || o->fmt == PS_OFMT_AUTO);
    int need_quiet = (o->fmt == PS_OFMT_QUIET);

    if (need_jsonl) jn = render_jsonl(f, jsonl_buf, sizeof(jsonl_buf));
    if (need_text)  tn = render_text (f, o->color, text_buf, sizeof(text_buf));
    if (need_quiet) tn = render_quiet(f, text_buf, sizeof(text_buf));

    pthread_mutex_lock(&o->lock);
    switch (f->severity) {
        case PS_SEV_INFO:     o->n_info++;     break;
        case PS_SEV_LOW:      o->n_low++;      break;
        case PS_SEV_MEDIUM:   o->n_medium++;   break;
        case PS_SEV_HIGH:     o->n_high++;     break;
        case PS_SEV_CRITICAL: o->n_critical++; break;
    }
    if (o->fmt == PS_OFMT_TEXT || o->fmt == PS_OFMT_QUIET || o->fmt == PS_OFMT_AUTO) {
        if (tn > 0) write_all(o->stdout_fd, text_buf, (size_t)tn);
    } else {
        if (jn > 0) write_all(o->stdout_fd, jsonl_buf, (size_t)jn);
    }
    if (o->append_fd >= 0 && jn > 0) {
        write_all(o->append_fd, jsonl_buf, (size_t)jn);
    }
    pthread_mutex_unlock(&o->lock);
}

void ps_output_emit_raw_jsonl(struct ps_output *o, int severity,
                              const char *line, size_t len) {
    if (!o || !line || len == 0) return;
    pthread_mutex_lock(&o->lock);
    switch (severity) {
        case PS_SEV_INFO:     o->n_info++;     break;
        case PS_SEV_LOW:      o->n_low++;      break;
        case PS_SEV_MEDIUM:   o->n_medium++;   break;
        case PS_SEV_HIGH:     o->n_high++;     break;
        case PS_SEV_CRITICAL: o->n_critical++; break;
        default: break;
    }
    if (o->fmt != PS_OFMT_QUIET) {
        write_all(o->stdout_fd, line, len);
    }
    if (o->append_fd >= 0) {
        write_all(o->append_fd, line, len);
    }
    pthread_mutex_unlock(&o->lock);
}

void ps_output_summary(const struct ps_output *o, const char *run_id, long duration_ms) {
    unsigned int total = o->n_info + o->n_low + o->n_medium + o->n_high + o->n_critical;
    fprintf(stderr,
            "run %s: %u findings (info=%u low=%u medium=%u high=%u critical=%u) in %ld ms\n",
            run_id, total,
            o->n_info, o->n_low, o->n_medium, o->n_high, o->n_critical,
            duration_ms);
}

void ps_output_close(struct ps_output *o) {
    if (o->append_fd >= 0) {
        close(o->append_fd);
        o->append_fd = -1;
    }
    pthread_mutex_destroy(&o->lock);
}
