#include "../output/output.h"
#include "finding.h"
#include "ulid.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void capture_to_buf(int fmt_force, int color, const struct ps_finding *f,
                           char *out, size_t outsz) {
    char path[] = "/tmp/ps_test_out_XXXXXX";
    int fd = mkstemp(path);
    assert(fd >= 0);

    struct ps_output o;
    struct ps_output_opts opts = {0};
    opts.fmt_force  = fmt_force;
    opts.color      = color;
    opts.target_fd  = fd;
    opts.assume_tty = (color ? 1 : 0);
    assert(ps_output_init(&o, &opts) == 0);
    ps_output_emit(&o, f);
    ps_output_close(&o);

    lseek(fd, 0, SEEK_SET);
    ssize_t r = read(fd, out, outsz - 1);
    out[r > 0 ? r : 0] = '\0';
    close(fd);
    unlink(path);
}

static void make_finding(struct ps_finding *f) {
    char run_id[PS_ULID_STRLEN + 1];
    ps_ulid_new(run_id, sizeof(run_id));
    ps_finding_init(f, run_id, "cli.audit.tls", "h", "tls.weak_protocol",
                    PS_SEV_HIGH, PS_CONF_FIRM, "TLS 1.0");
    ps_finding_set_target_ip(f, "10.0.0.42", 443);
}

static void test_jsonl_format(void) {
    struct ps_finding f; make_finding(&f);
    char buf[2048];
    capture_to_buf(PS_OFMT_JSONL, 0, &f, buf, sizeof(buf));
    assert(strstr(buf, "\"kind\":\"tls.weak_protocol\""));
    size_t L = strlen(buf);
    assert(L > 0 && buf[L - 1] == '\n');
}

static void test_text_format_no_color(void) {
    struct ps_finding f; make_finding(&f);
    char buf[1024];
    capture_to_buf(PS_OFMT_TEXT, 0, &f, buf, sizeof(buf));
    assert(strstr(buf, "tls.weak_protocol"));
    assert(strstr(buf, "10.0.0.42:443"));
    assert(strstr(buf, "TLS 1.0"));
    assert(strstr(buf, "\x1b[") == NULL);
}

static void test_text_format_with_color(void) {
    struct ps_finding f; make_finding(&f);
    char buf[1024];
    capture_to_buf(PS_OFMT_TEXT, 1, &f, buf, sizeof(buf));
    assert(strstr(buf, "\x1b[") != NULL);
}

static void test_quiet_format(void) {
    struct ps_finding f; make_finding(&f);
    char buf[1024];
    capture_to_buf(PS_OFMT_QUIET, 0, &f, buf, sizeof(buf));
    assert(strstr(buf, "high\ttls.weak_protocol"));
    assert(strstr(buf, "\t10.0.0.42:443\t"));
}

int main(void) {
    test_jsonl_format();
    test_text_format_no_color();
    test_text_format_with_color();
    test_quiet_format();
    printf("test_output: OK\n");
    return 0;
}
