#include "../finding.h"
#include "../ulid.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static int contains(const char *hay, const char *needle) {
    return strstr(hay, needle) != NULL;
}

static void test_minimal_finding_to_json(void) {
    char run_id[PS_ULID_STRLEN + 1];
    ps_ulid_new(run_id, sizeof(run_id));

    struct ps_finding f;
    ps_finding_init(&f, run_id, "cli.audit.tls", "test-host", "tls.weak_protocol",
                    PS_SEV_HIGH, PS_CONF_FIRM, "TLS 1.0 negotiated");
    ps_finding_set_target_ip(&f, "10.0.0.42", 443);

    char buf[2048];
    int n = ps_finding_to_json(&f, buf, sizeof(buf));
    assert(n > 0);
    assert(contains(buf, "\"v\":1"));
    assert(contains(buf, "\"run_id\":"));
    assert(contains(buf, run_id));
    assert(contains(buf, "\"source\":\"cli.audit.tls\""));
    assert(contains(buf, "\"host\":\"test-host\""));
    assert(contains(buf, "\"kind\":\"tls.weak_protocol\""));
    assert(contains(buf, "\"severity\":\"high\""));
    assert(contains(buf, "\"confidence\":\"firm\""));
    assert(contains(buf, "\"title\":\"TLS 1.0 negotiated\""));
    assert(contains(buf, "\"target\":{"));
    assert(contains(buf, "\"ip\":\"10.0.0.42\""));
    assert(contains(buf, "\"port\":443"));
    /* JSONL: exactly one line, ends with newline */
    assert(buf[n - 1] == '\n');
    int newlines = 0;
    for (int i = 0; i < n; i++) if (buf[i] == '\n') newlines++;
    assert(newlines == 1);
}

static void test_severity_enum_strings(void) {
    assert(strcmp(ps_severity_str(PS_SEV_INFO),     "info")     == 0);
    assert(strcmp(ps_severity_str(PS_SEV_LOW),      "low")      == 0);
    assert(strcmp(ps_severity_str(PS_SEV_MEDIUM),   "medium")   == 0);
    assert(strcmp(ps_severity_str(PS_SEV_HIGH),     "high")     == 0);
    assert(strcmp(ps_severity_str(PS_SEV_CRITICAL), "critical") == 0);
}

static void test_json_escaping(void) {
    char run_id[PS_ULID_STRLEN + 1];
    ps_ulid_new(run_id, sizeof(run_id));
    struct ps_finding f;
    ps_finding_init(&f, run_id, "cli.audit.tls", "h", "tls.x",
                    PS_SEV_INFO, PS_CONF_FIRM, "weird \"quotes\" and \\back\\ and \n");
    char buf[1024];
    int n = ps_finding_to_json(&f, buf, sizeof(buf));
    assert(n > 0);
    assert(contains(buf, "\\\"quotes\\\""));
    assert(contains(buf, "\\\\back\\\\"));
    assert(contains(buf, "\\n"));
}

static void test_optional_via_agent(void) {
    char run_id[PS_ULID_STRLEN + 1];
    ps_ulid_new(run_id, sizeof(run_id));
    struct ps_finding f;
    ps_finding_init(&f, run_id, "agent.tls_probe", "trunkbox", "tls.weak_protocol",
                    PS_SEV_HIGH, PS_CONF_FIRM, "TLS 1.0");
    ps_finding_set_via_agent(&f, "trunkbox");
    char buf[1024];
    int n = ps_finding_to_json(&f, buf, sizeof(buf));
    assert(n > 0);
    assert(contains(buf, "\"via_agent\":\"trunkbox\""));
}

static void test_evidence_blob_passthrough(void) {
    char run_id[PS_ULID_STRLEN + 1];
    ps_ulid_new(run_id, sizeof(run_id));
    struct ps_finding f;
    ps_finding_init(&f, run_id, "cli.audit.tls", "h", "tls.weak_cipher",
                    PS_SEV_HIGH, PS_CONF_FIRM, "weak cipher");
    ps_finding_set_evidence_json(&f, "{\"cipher\":\"DES-CBC3-SHA\"}");
    char buf[1024];
    int n = ps_finding_to_json(&f, buf, sizeof(buf));
    assert(n > 0);
    assert(contains(buf, "\"evidence\":{\"cipher\":\"DES-CBC3-SHA\"}"));
}

int main(void) {
    test_minimal_finding_to_json();
    test_severity_enum_strings();
    test_json_escaping();
    test_optional_via_agent();
    test_evidence_blob_passthrough();
    printf("test_finding: OK\n");
    return 0;
}
