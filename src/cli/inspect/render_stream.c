#include "render.h"
#include "proc_profile_delta.h"
#include <stdio.h>

void ps_inspect_stream_init(struct ps_inspect_stream *st) { st->started = 0; }

void ps_inspect_stream_render(struct ps_inspect_stream *st, struct ps_pp_model *m,
                              const char *host) {
    static char buf[1 << 20];   /* 1 MiB: a full-model keyframe (up to 512 entities) fits */
    if (!st->started) {
        if (ps_pp_keyframe_json(m, host, buf, sizeof buf) > 0) { fputs(buf, stdout); fputc('\n', stdout); }
        /* The keyframe carries full state; clear dirty flags WITHOUT a delta (which
         * would bump seq and break alignment). Keyframe is seq 0, first delta seq 1. */
        for (int i = 0; i < m->nent; i++) m->ent[i].dirty = 0;
        m->seq = 0;
        st->started = 1;
        fflush(stdout);
        return;
    }
    int n = ps_pp_delta_json(m, buf, sizeof buf);
    if (n > 0) { fputs(buf, stdout); fputc('\n', stdout); fflush(stdout); }
}
