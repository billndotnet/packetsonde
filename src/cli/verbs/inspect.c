#include "../verbs.h"
#include "../inspect/render.h"
#include "../inspect/subject.h"
#include "proc_profile.h"
#include "activity_record.h"
#include "ulid.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/time.h>

static int64_t now_ms(void) {
    struct timeval tv; gettimeofday(&tv, NULL);
    return (int64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

int ps_verb_inspect_run(int argc, char **argv, const struct ps_args *opts) {
    const char *exe = NULL, *source = "/var/lib/packetsonde/activity.jsonl";
    const char *bl_dir = getenv("PS_DETECT_BASELINE_STATE_DIR");
    int pid = -1, stream = 0, once = 0;
    double interval = 1.0;
    static struct option lo[] = {
        {"pid", required_argument, 0, 'P'}, {"exe", required_argument, 0, 'e'},
        {"source", required_argument, 0, 's'}, {"interval", required_argument, 0, 'i'},
        {"stream", no_argument, 0, 'S'}, {"once", no_argument, 0, 'o'}, {0,0,0,0}
    };
    optind = 1; int c;
    while ((c = getopt_long(argc, argv, "", lo, NULL)) != -1) {
        if (c=='P') pid = atoi(optarg);
        else if (c=='e') exe = optarg;
        else if (c=='s') source = optarg;
        else if (c=='i') interval = atof(optarg);
        else if (c=='S') stream = 1;
        else if (c=='o') once = 1;
        else { fprintf(stderr, "usage: packetsonde inspect (--pid N | --exe PATH) [--source F] [--interval S] [--stream] [--once]\n"); return 2; }
    }
    if ((pid < 0) == (exe == NULL)) {
        fprintf(stderr, "inspect: exactly one of --pid or --exe is required\n"); return 2;
    }
    if (opts->via_count > 0) { fprintf(stderr, "inspect: --via not supported yet (Phase 2)\n"); return 2; }

    struct ps_inspect_subject subj;
    struct ps_pp_subject psubj; memset(&psubj, 0, sizeof psubj);
    if (pid >= 0) { ps_subject_init_pid(&subj, pid); psubj.mode = PS_PP_BY_PID; psubj.pid = pid; }
    else { ps_subject_init_exe(&subj, exe); psubj.mode = PS_PP_BY_EXE; snprintf(psubj.exe, sizeof psubj.exe, "%s", exe); }

    char epoch[PS_ULID_STRLEN + 1]; ps_ulid_new(epoch, sizeof epoch);
    struct ps_pp_model model; ps_pp_init(&model, &psubj, epoch);
    if (exe) ps_pp_load_baseline(&model, exe, bl_dir);

    char host[256] = ""; gethostname(host, sizeof host);
    int to_tty = isatty(STDOUT_FILENO) && !stream;
    struct ps_inspect_stream sstate; ps_inspect_stream_init(&sstate);

    FILE *f = fopen(source, "r");
    if (!f) { fprintf(stderr, "inspect: cannot open %s (is [detect] sink configured?)\n", source); return 1; }

    char line[16384];
    int64_t last_render = 0;
    for (;;) {
        while (fgets(line, sizeof line, f)) {
            struct ps_activity a;
            if (ps_activity_from_json(line, &a) != 0) continue;
            if (!ps_subject_match(&subj, &a)) continue;
            ps_pp_fold(&model, &a, now_ms());
        }
        int64_t t = now_ms();
        if (t - last_render >= (int64_t)(interval * 1000) || once) {
            ps_pp_tick_rates(&model, t);
            if (to_tty) ps_inspect_tty_render(&model, host);
            else ps_inspect_stream_render(&sstate, &model, host);
            last_render = t;
        }
        if (once) break;
        clearerr(f);
        usleep(200000);
    }
    fclose(f);
    return 0;
}
