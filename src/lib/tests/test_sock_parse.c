#include "sock_parse.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>

/* One real-shaped /proc/net/tcp line: local 10.0.0.5:445 (0500000A:01BD),
 * remote 203.0.113.5:51344 (057100CB:C890), state 01 (ESTABLISHED), inode 99887. */
static const char *TCP =
"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
"   0: 0500000A:01BD 057100CB:C890 01 00000000:00000000 00:00000000 00000000     0        0 99887 1 0000 ...\n";

int main(void) {
    struct ps_sock_ep eps[8];
    int n = ps_sock_parse_procnet("tcp", TCP, eps, 8);
    assert(n == 1);
    assert(eps[0].inode == 99887UL);
    assert(strcmp(eps[0].laddr, "10.0.0.5:445") == 0);
    assert(strcmp(eps[0].raddr, "203.0.113.5:51344") == 0);
    assert(strcmp(eps[0].state, "ESTABLISHED") == 0);
    assert(strcmp(eps[0].proto, "tcp") == 0);

    struct ps_sock_ep hit;
    assert(ps_sock_find_by_inode(eps, n, 99887UL, &hit) == 0);
    assert(strcmp(hit.raddr, "203.0.113.5:51344") == 0);
    assert(ps_sock_find_by_inode(eps, n, 12345UL, &hit) == -1);

    printf("test_sock_parse: OK\n");
    return 0;
}
