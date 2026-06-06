#include "fan_monitor.h"
#include "provenance.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

static void wr(const char *p, const char *c){ FILE*f=fopen(p,"w"); assert(f); fputs(c,f); fclose(f); }

int main(void) {
    char root[] = "/tmp/ps_fan_XXXXXX"; assert(mkdtemp(root));
    char p[320], d[320];
    snprintf(d, sizeof d, "%s/net", root); mkdir(d, 0755);
    snprintf(p, sizeof p, "%s/net/tcp", root);
    wr(p, "hdr\n   0: 0500000A:01BD 057100CB:C890 01 00000000:00000000 00:00000000 00000000 0 0 99887 1\n");
    snprintf(p, sizeof p, "%s/net/tcp6", root); wr(p, "h\n");
    snprintf(p, sizeof p, "%s/net/udp",  root); wr(p, "h\n");
    snprintf(p, sizeof p, "%s/net/udp6", root); wr(p, "h\n");
    /* leaf 1234 (sh) -> 1190 (smbd, holds socket) -> init */
    snprintf(d, sizeof d, "%s/1234", root); mkdir(d, 0755);
    snprintf(p, sizeof p, "%s/1234/stat", root);
    wr(p, "1234 (sh) S 1190 1234 1190 0 -1 0 0 0 0 0 1 1 0 0 20 0 1 0 5550001 0\n");
    snprintf(p, sizeof p, "%s/1234/cgroup", root); wr(p, "0::/system.slice/smbd.service\n");
    snprintf(d, sizeof d, "%s/1234/attr", root); mkdir(d, 0755);
    snprintf(p, sizeof p, "%s/1234/attr/current", root); wr(p, "unconfined\n");
    snprintf(p, sizeof p, "%s/1234/cmdline", root); wr(p, "sh");
    snprintf(d, sizeof d, "%s/1190", root); mkdir(d, 0755);
    snprintf(p, sizeof p, "%s/1190/stat", root);
    wr(p, "1190 (smbd) S 1 1190 1190 0 -1 0 0 0 0 0 1 1 0 0 20 0 1 0 4440002 0\n");
    snprintf(p, sizeof p, "%s/1190/cgroup", root); wr(p, "0::/system.slice/smbd.service\n");
    snprintf(d, sizeof d, "%s/1190/attr", root); mkdir(d, 0755);
    snprintf(p, sizeof p, "%s/1190/attr/current", root); wr(p, "unconfined\n");
    snprintf(p, sizeof p, "%s/1190/cmdline", root); wr(p, "/usr/sbin/smbd");
    snprintf(d, sizeof d, "%s/1190/fd", root); mkdir(d, 0755);
    snprintf(p, sizeof p, "%s/1190/fd/3", root); assert(symlink("socket:[99887]", p) == 0);

    char json[8192];
    /* not suppressed: read of /etc/shadow */
    int n = ps_fan_build_record(root, 1234, "/etc/shadow", "open", 1, "", 16, NULL, json, sizeof json);
    assert(n > 0);
    assert(strstr(json, "\"path\":\"/etc/shadow\""));
    assert(strstr(json, "\"comm\":\"sh\""));
    assert(strstr(json, "\"start_ticks\":5550001"));   /* leaf starttime */
    assert(strstr(json, "\"start_ticks\":4440002"));   /* ancestor smbd starttime */
    assert(strstr(json, "\"owner_comm\":\"smbd\""));       /* ancestor socket attributed */
    assert(strstr(json, "\"raddr\":\"203.0.113.5:51344\""));

    /* provenance: executable write under a transient root stamps prov_trigger.
     * Create a real +x file (the classifier stats the real path for the mode). */
    char exe_path[320]; snprintf(exe_path, sizeof exe_path, "%s/payload", root);
    wr(exe_path, "#!/bin/sh\n"); chmod(exe_path, 0755);
    struct ps_prov_cfg prov = { .enabled = 1, .transient_paths = root, .sensitive_paths = "" };
    int pn = ps_fan_build_record(root, 1234, exe_path, "write", 0, "", 16, &prov, json, sizeof json);
    assert(pn > 0);
    assert(strstr(json, "\"prov_trigger\":\"write_executable\""));
    /* a plain read open under the same root does NOT stamp a trigger */
    int rn = ps_fan_build_record(root, 1234, exe_path, "open", 1, "", 16, &prov, json, sizeof json);
    assert(rn > 0 && strstr(json, "prov_trigger") == NULL);

    /* suppressed read returns 0 (no record) */
    int s = ps_fan_build_record(root, 1234, "/usr/lib/x.so", "open", 1, "/usr/lib", 16, NULL, json, sizeof json);
    assert(s == 0);
    printf("test_fan_build: OK\n");
    return 0;
}
