#include "sock_snapshot.h"
#include "activity_record.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

static void wr(const char *p, const char *c){ FILE*f=fopen(p,"w"); assert(f); fputs(c,f); fclose(f); }

int main(void) {
    char root[] = "/tmp/ps_sock_XXXXXX"; assert(mkdtemp(root));
    char p[320], d[320];
    /* <root>/net/tcp with inode 99887 (10.0.0.5:445 <- 203.0.113.5:51344, ESTABLISHED) */
    snprintf(d, sizeof d, "%s/net", root); mkdir(d, 0755);
    snprintf(p, sizeof p, "%s/net/tcp", root);
    wr(p, "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
          "   0: 0500000A:01BD 057100CB:C890 01 00000000:00000000 00:00000000 00000000     0        0 99887 1\n");
    snprintf(p, sizeof p, "%s/net/tcp6", root); wr(p, "header\n");
    snprintf(p, sizeof p, "%s/net/udp",  root); wr(p, "header\n");
    snprintf(p, sizeof p, "%s/net/udp6", root); wr(p, "header\n");
    /* pid 1190 holds fd -> socket:[99887] */
    snprintf(d, sizeof d, "%s/1190", root); mkdir(d, 0755);
    snprintf(d, sizeof d, "%s/1190/fd", root); mkdir(d, 0755);
    snprintf(p, sizeof p, "%s/1190/fd/3", root);
    assert(symlink("socket:[99887]", p) == 0);

    int pids[1]   = {1190};
    const char *comms[1] = {"smbd"};
    int depths[1] = {1};
    struct ps_act_socket out[8];
    int n = ps_sock_snapshot(root, pids, 1, comms, depths, out, 8);
    assert(n == 1);
    assert(out[0].owner_pid == 1190 && out[0].depth == 1);
    assert(strcmp(out[0].owner_comm, "smbd") == 0);
    assert(strcmp(out[0].raddr, "203.0.113.5:51344") == 0);
    assert(strcmp(out[0].state, "ESTABLISHED") == 0);
    printf("test_sock_snapshot: OK\n");
    return 0;
}
