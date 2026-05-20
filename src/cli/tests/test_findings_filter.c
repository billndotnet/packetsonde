#include "../findings_util/filter.h"
#include "../findings_util/reader.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static const char *LINE_TLS_HIGH =
    "{\"v\":1,\"id\":\"01H\",\"run_id\":\"R\",\"ts\":\"t\","
    "\"source\":\"cli.audit.tls\",\"host\":\"h\","
    "\"kind\":\"tls.weak_cipher\",\"severity\":\"high\",\"confidence\":\"firm\","
    "\"title\":\"x\",\"target\":{\"ip\":\"10.0.0.1\",\"port\":443}}";

static const char *LINE_DNS_LOW =
    "{\"v\":1,\"id\":\"01J\",\"run_id\":\"R\",\"ts\":\"t\","
    "\"source\":\"cli.audit.dns\",\"host\":\"h\","
    "\"kind\":\"dns.version_leak\",\"severity\":\"low\",\"confidence\":\"firm\","
    "\"title\":\"y\",\"target\":{\"ip\":\"8.8.8.8\"}}";

static void test_parse_minimal(void) {
    struct ps_finding_lite f;
    assert(ps_finding_parse_line(LINE_TLS_HIGH, &f) == 0);
    assert(strcmp(f.kind, "tls.weak_cipher") == 0);
    assert(f.severity == PS_SEV_HIGH);
    assert(strcmp(f.target, "10.0.0.1:443") == 0);
}

static void test_filter_kind_eq(void) {
    struct ps_finding_filter F;
    assert(ps_filter_parse("kind=tls.weak_cipher", &F) == 0);
    struct ps_finding_lite f1, f2;
    ps_finding_parse_line(LINE_TLS_HIGH, &f1);
    ps_finding_parse_line(LINE_DNS_LOW,  &f2);
    assert(ps_filter_eval(&F, &f1) == 1);
    assert(ps_filter_eval(&F, &f2) == 0);
    ps_filter_destroy(&F);
}

static void test_filter_severity_ge(void) {
    struct ps_finding_filter F;
    assert(ps_filter_parse("severity>=medium", &F) == 0);
    struct ps_finding_lite f1, f2;
    ps_finding_parse_line(LINE_TLS_HIGH, &f1);
    ps_finding_parse_line(LINE_DNS_LOW,  &f2);
    assert(ps_filter_eval(&F, &f1) == 1);
    assert(ps_filter_eval(&F, &f2) == 0);
    ps_filter_destroy(&F);
}

static void test_filter_kind_prefix(void) {
    struct ps_finding_filter F;
    assert(ps_filter_parse("kind~tls.", &F) == 0);
    struct ps_finding_lite f1, f2;
    ps_finding_parse_line(LINE_TLS_HIGH, &f1);
    ps_finding_parse_line(LINE_DNS_LOW,  &f2);
    assert(ps_filter_eval(&F, &f1) == 1);
    assert(ps_filter_eval(&F, &f2) == 0);
    ps_filter_destroy(&F);
}

int main(void) {
    test_parse_minimal();
    test_filter_kind_eq();
    test_filter_severity_ge();
    test_filter_kind_prefix();
    printf("test_findings_filter: OK\n");
    return 0;
}
