#include "render.h"
#include <stdio.h>
#include <string.h>

static const char *glyph(enum ps_pp_verdict v) {
    return v == PS_PP_ANOMALY ? "⚠" : v == PS_PP_NOVEL ? "✚" : " ";
}

/* Print up to 12 entities of one kind, most-recent first. Read-only: it sorts a
 * local array of indices by last_ms and never mutates the model. */
static void section(struct ps_pp_model *m, enum ps_pp_kind kind, const char *label) {
    int idx[PS_PP_MAX_ENT]; int n = 0;
    for (int i = 0; i < m->nent; i++)
        if (m->ent[i].present && m->ent[i].kind == kind) idx[n++] = i;
    printf("%s (%d)\n", label, n);
    for (int i = 1; i < n; i++) {              /* insertion sort by last_ms desc */
        int v = idx[i]; int j = i - 1;
        while (j >= 0 && m->ent[idx[j]].last_ms < m->ent[v].last_ms) { idx[j+1] = idx[j]; j--; }
        idx[j+1] = v;
    }
    for (int r = 0; r < n && r < 12; r++) {
        struct ps_pp_entity *e = &m->ent[idx[r]];
        if (e->state[0])
            printf(" %s %-40s %-6s %6llu\n", glyph(e->verdict), e->value, e->state, (unsigned long long)e->count);
        else
            printf(" %s %-47s %6llu\n", glyph(e->verdict), e->value, (unsigned long long)e->count);
    }
}

void ps_inspect_tty_render(struct ps_pp_model *m, const char *host) {
    printf("\x1b[H\x1b[2J");   /* cursor home + clear screen */
    printf("inspect %s %s  uid%d  cg:%s  MAC:%s\n",
           m->subject.mode == PS_PP_BY_PID ? "pid" : "exe",
           m->subject.mode == PS_PP_BY_PID ? "" : m->subject.exe,
           m->subject.uid, m->subject.cgroup[0] ? m->subject.cgroup : "-",
           m->subject.mac_label[0] ? m->subject.mac_label : "-");
    if (m->subject.mode == PS_PP_BY_PID) printf("  pid %d  %s\n", m->subject.pid, m->subject.exe);
    printf("host %s   rates: open %.0f/s  connect %.0f/s  exec %.0f/s",
           host, m->rates.open_s, m->rates.connect_s, m->rates.exec_s);
    if (m->subject.nanc > 0) {
        printf("   ancestry: ");
        for (int i = m->subject.nanc - 1; i >= 0; i--)
            printf("%s%s", m->subject.anc[i].comm, i ? "→" : "");
    }
    printf("\n✚ novel  ⚠ anomaly\n");
    section(m, PS_PP_FILE, "FILES");
    section(m, PS_PP_DEST, "NETWORK");
    section(m, PS_PP_PROC, "PROCESSES");
    printf("[q]uit (Ctrl-C)\n");
    fflush(stdout);
}
