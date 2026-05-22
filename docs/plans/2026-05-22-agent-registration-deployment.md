# packetsonded Agent Registration + Deployment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `packetsonded` enroll with central (`POST /register`), then check in (`POST /checkin`) so it appears validated + online in central's Fleet — plus the deployment glue to install/bootstrap it.

**Architecture:** A small hand-rolled HTTP/1.1 client over the OpenSSL the agent already links (`src/lib/http_client`), split into pure URL-parse / request-build / response-parse functions (unit-testable) + a thin TLS-connect orchestrator. A registration routine (`src/lib/registration`) builds the JSON via the existing `ps_json` builder, signs identity from the existing `keystore`, sha256s its own binary, POSTs, and writes a `registered` marker. One idempotent routine, two triggers: a `packetsonde register` CLI verb and daemon self-enroll on boot, plus a periodic checkin. Config is a new `[central]` block read via the existing `ps_config` (arbitrary sections already supported). Deploy via a `packetsonded-bootstrap` script + an rna-salt state.

**Tech Stack:** C11, OpenSSL (already linked), CMake/CTest, the existing `ps_json`/`ps_config`/`ps_keystore` libs; shell (bootstrap) + Salt (fleet).

**Spec:** `docs/specs/2026-05-22-agent-registration-deployment-design.md`.

**Central contract (already live in rna-packetsonde):**
- `POST {base}/api/v1/packetsonde/register` `{agent_id,pubkey,binary_checksum,deployment_mode,provenance,ip_address}` → `201 {agent_id,status}`
- `POST {base}/api/v1/packetsonde/checkin` `{agent_id,uptime_seconds,config_version,agent_version,key_rotation_status}` → `200 {ok:true}`

---

## File Structure

```
src/lib/
├── http_client.h / .c     # ps_url_parse, ps_http_build_request, ps_http_parse_response, ps_http_request
├── registration.h / .c    # ps_reg_build_payload, ps_reg_marker_*, ps_sha256_file, ps_register
src/lib/tests/
├── test_http_client.c     # url parse + request build + response parse
├── test_registration.c    # payload JSON + marker idempotency + sha256(fixture)
src/cli/verbs/
└── register.c             # `packetsonde register` verb -> ps_register(provenance=salt)
src/cli/
└── verbs.c                # +register verb in the registry table   (Modify)
src/agent/src/
├── main.c                 # self-enroll on boot + start checkin task   (Modify)
└── central_checkin.h / .c # periodic POST /checkin loop
packaging/
└── bootstrap              # extend: packetsonded-bootstrap --central --mode ...   (Modify)
# (rna-salt repo)
salt/packetsonde/          # init.sls + packetsonded.toml.jinja + pillar.example
```

**Interfaces locked here (names must match across tasks):**
- `http_client.h`:
  - `struct ps_url { char scheme[8]; char host[256]; int port; char path[512]; };`
  - `int ps_url_parse(const char *url, struct ps_url *out);` → 0 ok, -1 bad.
  - `int ps_http_build_request(char *buf, size_t cap, const char *method, const struct ps_url *u, const char *body, const char *extra_headers);` → bytes written or -1.
  - `int ps_http_parse_response(const char *raw, size_t len, int *status_out, const char **body_out);` → 0 ok.
  - `struct ps_http_opts { int verify; const char *ca_cert; int timeout_s; };`
  - `int ps_http_request(const char *method, const char *url, const char *body, const struct ps_http_opts *opts, int *status_out, char *resp_buf, size_t resp_cap);` → 0 ok, -1 transport error.
- `registration.h`:
  - `struct ps_reg_input { const char *agent_id; const uint8_t *pubkey; const char *binary_checksum; const char *deployment_mode; const char *provenance; const char *ip_address; };`
  - `int ps_reg_build_payload(char *buf, size_t cap, const struct ps_reg_input *in);` → bytes or -1.
  - `int ps_sha256_file(const char *path, char *out_hex /* >=65 */);` → 0 ok.
  - `int ps_reg_marker_read(const char *path, char *agent_id_out, size_t cap);` → 0 if present.
  - `int ps_reg_marker_write(const char *path, const char *agent_id, const char *status);` → 0 ok.
  - `enum ps_reg_result { PS_REG_OK, PS_REG_ALREADY, PS_REG_HTTP_ERR, PS_REG_LOCAL_ERR };`
  - `enum ps_reg_result ps_register(const struct ps_config *cfg, const char *provenance, int force);`

---

## Task 1: HTTP client — pure functions (URL parse, request build, response parse)

**Files:**
- Create: `src/lib/http_client.h`, `src/lib/http_client.c`
- Test: `src/lib/tests/test_http_client.c`

- [ ] **Step 1: Write the failing test**

```c
/* src/lib/tests/test_http_client.c */
#include "http_client.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>

static void test_url_parse(void) {
    struct ps_url u;
    assert(ps_url_parse("https://central.example:8700/api/v1/packetsonde/register", &u) == 0);
    assert(strcmp(u.scheme, "https") == 0);
    assert(strcmp(u.host, "central.example") == 0);
    assert(u.port == 8700);
    assert(strcmp(u.path, "/api/v1/packetsonde/register") == 0);

    assert(ps_url_parse("http://10.0.1.10:8700/x", &u) == 0);
    assert(u.port == 8700 && strcmp(u.scheme, "http") == 0);

    /* default ports */
    assert(ps_url_parse("https://h/p", &u) == 0 && u.port == 443);
    assert(ps_url_parse("http://h", &u) == 0 && u.port == 80 && strcmp(u.path, "/") == 0);
    assert(ps_url_parse("ftp://h/x", &u) == -1);
}

static void test_build_request(void) {
    struct ps_url u; ps_url_parse("http://h:8700/r", &u);
    char buf[1024];
    int n = ps_http_build_request(buf, sizeof buf, "POST", &u, "{\"a\":1}", NULL);
    assert(n > 0);
    assert(strstr(buf, "POST /r HTTP/1.1\r\n"));
    assert(strstr(buf, "Host: h:8700\r\n"));
    assert(strstr(buf, "Content-Type: application/json\r\n"));
    assert(strstr(buf, "Content-Length: 7\r\n"));
    assert(strstr(buf, "Connection: close\r\n"));
    assert(strstr(buf, "\r\n\r\n{\"a\":1}"));
}

static void test_parse_response(void) {
    const char *raw = "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\n"
                      "Content-Length: 9\r\n\r\n{\"ok\":1}\n";
    int status; const char *body;
    assert(ps_http_parse_response(raw, strlen(raw), &status, &body) == 0);
    assert(status == 201);
    assert(strncmp(body, "{\"ok\":1}", 8) == 0);
}

int main(void) {
    test_url_parse(); test_build_request(); test_parse_response();
    printf("test_http_client: OK\n");
    return 0;
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd build && cmake .. -DBUILD_TESTING=ON >/dev/null && make test_http_client 2>&1 | tail -5`
Expected: FAIL — `http_client.h` not found / undefined references.

- [ ] **Step 3: Create `src/lib/http_client.h`**

```c
#ifndef PS_HTTP_CLIENT_H
#define PS_HTTP_CLIENT_H
#include <stddef.h>

struct ps_url { char scheme[8]; char host[256]; int port; char path[512]; };
struct ps_http_opts { int verify; const char *ca_cert; int timeout_s; };

int ps_url_parse(const char *url, struct ps_url *out);
int ps_http_build_request(char *buf, size_t cap, const char *method,
                          const struct ps_url *u, const char *body,
                          const char *extra_headers);
int ps_http_parse_response(const char *raw, size_t len, int *status_out,
                           const char **body_out);
int ps_http_request(const char *method, const char *url, const char *body,
                    const struct ps_http_opts *opts, int *status_out,
                    char *resp_buf, size_t resp_cap);
#endif
```

- [ ] **Step 4: Create `src/lib/http_client.c` (pure functions only for now)**

```c
#include "http_client.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int ps_url_parse(const char *url, struct ps_url *o) {
    if (!url || !o) return -1;
    memset(o, 0, sizeof *o);
    const char *p;
    if (strncmp(url, "https://", 8) == 0) { strcpy(o->scheme, "https"); o->port = 443; p = url + 8; }
    else if (strncmp(url, "http://", 7) == 0) { strcpy(o->scheme, "http"); o->port = 80; p = url + 7; }
    else return -1;

    const char *slash = strchr(p, '/');
    const char *colon = strchr(p, ':');
    size_t hostlen;
    if (colon && (!slash || colon < slash)) {
        hostlen = (size_t)(colon - p);
        o->port = atoi(colon + 1);
    } else {
        hostlen = slash ? (size_t)(slash - p) : strlen(p);
    }
    if (hostlen == 0 || hostlen >= sizeof o->host) return -1;
    memcpy(o->host, p, hostlen);
    o->host[hostlen] = 0;

    if (slash) {
        if (strlen(slash) >= sizeof o->path) return -1;
        strcpy(o->path, slash);
    } else {
        strcpy(o->path, "/");
    }
    return 0;
}

int ps_http_build_request(char *buf, size_t cap, const char *method,
                          const struct ps_url *u, const char *body,
                          const char *extra_headers) {
    size_t blen = body ? strlen(body) : 0;
    int n = snprintf(buf, cap,
        "%s %s HTTP/1.1\r\n"
        "Host: %s:%d\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "%s"
        "\r\n"
        "%s",
        method, u->path, u->host, u->port, blen,
        extra_headers ? extra_headers : "",
        body ? body : "");
    if (n < 0 || (size_t)n >= cap) return -1;
    return n;
}

int ps_http_parse_response(const char *raw, size_t len, int *status_out,
                           const char **body_out) {
    if (!raw || len < 12 || strncmp(raw, "HTTP/1.", 7) != 0) return -1;
    const char *sp = strchr(raw, ' ');
    if (!sp) return -1;
    *status_out = atoi(sp + 1);
    const char *sep = strstr(raw, "\r\n\r\n");
    *body_out = sep ? sep + 4 : raw + len;  /* empty body -> end */
    return 0;
}
```

- [ ] **Step 5: Wire the test into `src/lib/CMakeLists.txt`**

After the existing `add_test(NAME test_discovery ...)` block, add:

```cmake
    add_executable(test_http_client tests/test_http_client.c)
    target_link_libraries(test_http_client PRIVATE packetsonde_lib)
    add_test(NAME test_http_client COMMAND test_http_client)
```

And ensure `http_client.c` is in the `packetsonde_lib` sources list (add `http_client.c` next to the other `src/lib/*.c` entries in the `add_library(packetsonde_lib ...)` call).

- [ ] **Step 6: Run to verify it passes**

Run: `cd build && cmake .. -DBUILD_TESTING=ON >/dev/null && make test_http_client >/dev/null && ctest -R '^test_http_client$' --output-on-failure`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add src/lib/http_client.h src/lib/http_client.c src/lib/tests/test_http_client.c src/lib/CMakeLists.txt
git commit -m "Add HTTP/1.1 client pure functions (url parse, request build, response parse)"
```

---

## Task 2: HTTP client — OpenSSL transport (`ps_http_request`)

**Files:**
- Modify: `src/lib/http_client.c`

- [ ] **Step 1: Append the transport implementation to `src/lib/http_client.c`**

```c
#include <openssl/ssl.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/time.h>

static int dial(const char *host, int port, int timeout_s) {
    char portstr[16]; snprintf(portstr, sizeof portstr, "%d", port);
    struct addrinfo hints = {0}, *res = NULL;
    hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, portstr, &hints, &res) != 0) return -1;
    int fd = -1;
    for (struct addrinfo *a = res; a; a = a->ai_next) {
        fd = socket(a->ai_family, a->ai_socktype, a->ai_protocol);
        if (fd < 0) continue;
        struct timeval tv = { timeout_s > 0 ? timeout_s : 10, 0 };
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
        if (connect(fd, a->ai_addr, a->ai_addrlen) == 0) break;
        close(fd); fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

/* Send req (len bytes) over fd or ssl; read response into buf (cap). */
static int io_exchange(int fd, SSL *ssl, const char *req, size_t reqlen,
                       char *buf, size_t cap) {
    size_t off = 0;
    while (off < reqlen) {
        int w = ssl ? SSL_write(ssl, req + off, (int)(reqlen - off))
                    : (int)write(fd, req + off, reqlen - off);
        if (w <= 0) return -1;
        off += (size_t)w;
    }
    size_t got = 0;
    for (;;) {
        if (got + 1 >= cap) break;  /* cap reached; truncate */
        int r = ssl ? SSL_read(ssl, buf + got, (int)(cap - 1 - got))
                    : (int)read(fd, buf + got, cap - 1 - got);
        if (r <= 0) break;
        got += (size_t)r;
    }
    buf[got] = 0;
    return (int)got;
}

int ps_http_request(const char *method, const char *url, const char *body,
                    const struct ps_http_opts *opts, int *status_out,
                    char *resp_buf, size_t resp_cap) {
    struct ps_url u;
    if (ps_url_parse(url, &u) != 0) return -1;

    char req[8192];
    int reqlen = ps_http_build_request(req, sizeof req, method, &u, body, NULL);
    if (reqlen < 0) return -1;

    int timeout_s = opts ? opts->timeout_s : 10;
    int fd = dial(u.host, u.port, timeout_s);
    if (fd < 0) return -1;

    int rc = -1;
    SSL_CTX *ctx = NULL; SSL *ssl = NULL;
    int is_https = strcmp(u.scheme, "https") == 0;

    if (is_https) {
        ctx = SSL_CTX_new(TLS_client_method());
        if (!ctx) { close(fd); return -1; }
        int verify = opts ? opts->verify : 1;
        if (verify) {
            SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
            if (opts && opts->ca_cert && opts->ca_cert[0])
                SSL_CTX_load_verify_locations(ctx, opts->ca_cert, NULL);
            else
                SSL_CTX_set_default_verify_paths(ctx);
        } else {
            SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
        }
        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, fd);
        SSL_set_tlsext_host_name(ssl, u.host);
        X509_VERIFY_PARAM_set1_host(SSL_get0_param(ssl), u.host, 0);
        if (SSL_connect(ssl) != 1) goto done;
    }

    if (io_exchange(fd, ssl, req, (size_t)reqlen, resp_buf, resp_cap) < 0) goto done;
    {
        const char *bodyp = NULL;
        if (ps_http_parse_response(resp_buf, strlen(resp_buf), status_out, &bodyp) != 0)
            goto done;
        /* shift body to front of resp_buf for the caller's convenience */
        if (bodyp && bodyp != resp_buf) memmove(resp_buf, bodyp, strlen(bodyp) + 1);
        rc = 0;
    }
done:
    if (ssl) { SSL_shutdown(ssl); SSL_free(ssl); }
    if (ctx) SSL_CTX_free(ctx);
    close(fd);
    return rc;
}
```

- [ ] **Step 2: Build to verify it compiles + existing test still passes**

Run: `cd build && make test_http_client >/dev/null 2>&1 && ctest -R '^test_http_client$' --output-on-failure`
Expected: PASS (pure-function tests unaffected; transport compiles against OpenSSL already linked to `packetsonde_lib`).

- [ ] **Step 3: Commit**

```bash
git add src/lib/http_client.c
git commit -m "Add OpenSSL transport for HTTP client (dial, optional TLS verify/CA, exchange)"
```

> Transport is exercised end-to-end in Task 8's integration test against live psdev.

---

## Task 3: Registration core (payload, sha256, marker)

**Files:**
- Create: `src/lib/registration.h`, `src/lib/registration.c`
- Test: `src/lib/tests/test_registration.c`

- [ ] **Step 1: Write the failing test**

```c
/* src/lib/tests/test_registration.c */
#include "registration.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static void test_payload(void) {
    uint8_t pub[32]; for (int i=0;i<32;i++) pub[i]=(uint8_t)i;
    struct ps_reg_input in = { "edge-07", pub, "sha256:abc", "host", "direct", "10.0.1.42" };
    char buf[1024];
    int n = ps_reg_build_payload(buf, sizeof buf, &in);
    assert(n > 0);
    assert(strstr(buf, "\"agent_id\":\"edge-07\""));
    assert(strstr(buf, "\"deployment_mode\":\"host\""));
    assert(strstr(buf, "\"provenance\":\"direct\""));
    assert(strstr(buf, "\"ip_address\":\"10.0.1.42\""));
    assert(strstr(buf, "\"pubkey\":\"AAECAwQF"));  /* base64 of 0,1,2,... */
}

static void test_sha256_file(void) {
    char tmp[] = "/tmp/ps_sha_XXXXXX";
    int fd = mkstemp(tmp); assert(fd >= 0);
    write(fd, "abc", 3); close(fd);
    char hex[65];
    assert(ps_sha256_file(tmp, hex) == 0);
    /* sha256("abc") */
    assert(strcmp(hex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") == 0);
    unlink(tmp);
}

static void test_marker(void) {
    char tmp[] = "/tmp/ps_marker_XXXXXX";
    int fd = mkstemp(tmp); assert(fd >= 0); close(fd); unlink(tmp);  /* want absent */
    char id[128];
    assert(ps_reg_marker_read(tmp, id, sizeof id) != 0);   /* absent */
    assert(ps_reg_marker_write(tmp, "edge-07", "pending") == 0);
    assert(ps_reg_marker_read(tmp, id, sizeof id) == 0 && strcmp(id, "edge-07") == 0);
    unlink(tmp);
}

int main(void) { test_payload(); test_sha256_file(); test_marker();
    printf("test_registration: OK\n"); return 0; }
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd build && cmake .. -DBUILD_TESTING=ON >/dev/null && make test_registration 2>&1 | tail -5`
Expected: FAIL — `registration.h` not found.

- [ ] **Step 3: Create `src/lib/registration.h`**

```c
#ifndef PS_REGISTRATION_H
#define PS_REGISTRATION_H
#include <stddef.h>
#include <stdint.h>

struct ps_config;  /* forward decl; from config.h */

struct ps_reg_input {
    const char *agent_id;
    const uint8_t *pubkey;        /* 32 bytes */
    const char *binary_checksum;
    const char *deployment_mode;
    const char *provenance;
    const char *ip_address;
};

enum ps_reg_result { PS_REG_OK, PS_REG_ALREADY, PS_REG_HTTP_ERR, PS_REG_LOCAL_ERR };

int ps_reg_build_payload(char *buf, size_t cap, const struct ps_reg_input *in);
int ps_sha256_file(const char *path, char *out_hex /* >= 65 */);
int ps_reg_marker_read(const char *path, char *agent_id_out, size_t cap);
int ps_reg_marker_write(const char *path, const char *agent_id, const char *status);

enum ps_reg_result ps_register(const struct ps_config *cfg,
                               const char *provenance, int force);
#endif
```

- [ ] **Step 4: Create `src/lib/registration.c` (core helpers; `ps_register` in Task 5)**

```c
#include "registration.h"
#include "json.h"
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>

static int b64(const uint8_t *in, size_t n, char *out, size_t cap) {
    int len = EVP_EncodeBlock((unsigned char *)out, in, (int)n);
    return (len < 0 || (size_t)len >= cap) ? -1 : len;
}

int ps_reg_build_payload(char *buf, size_t cap, const struct ps_reg_input *in) {
    char pub_b64[64];
    if (b64(in->pubkey, 32, pub_b64, sizeof pub_b64) < 0) return -1;
    struct ps_json j; ps_json_init(&j, buf, cap);
    ps_json_object_begin(&j);
    ps_json_key_string(&j, "agent_id", in->agent_id);
    ps_json_key_string(&j, "pubkey", pub_b64);
    ps_json_key_string(&j, "binary_checksum", in->binary_checksum);
    ps_json_key_string(&j, "deployment_mode", in->deployment_mode);
    ps_json_key_string(&j, "provenance", in->provenance);
    ps_json_key_string(&j, "ip_address", in->ip_address ? in->ip_address : "");
    ps_json_object_end(&j);
    if (ps_json_finish(&j) != 0) return -1;
    return (int)strlen(buf);
}

int ps_sha256_file(const char *path, char *out_hex) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    SHA256_CTX c; SHA256_Init(&c);
    unsigned char chunk[8192]; size_t r;
    while ((r = fread(chunk, 1, sizeof chunk, f)) > 0) SHA256_Update(&c, chunk, r);
    fclose(f);
    unsigned char md[SHA256_DIGEST_LENGTH]; SHA256_Final(md, &c);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) sprintf(out_hex + i*2, "%02x", md[i]);
    out_hex[64] = 0;
    return 0;
}

int ps_reg_marker_read(const char *path, char *agent_id_out, size_t cap) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    char line[256]; int found = -1;
    while (fgets(line, sizeof line, f)) {
        if (strncmp(line, "agent_id=", 9) == 0) {
            char *v = line + 9; v[strcspn(v, "\r\n")] = 0;
            snprintf(agent_id_out, cap, "%s", v); found = 0;
        }
    }
    fclose(f);
    return found;
}

int ps_reg_marker_write(const char *path, const char *agent_id, const char *status) {
    FILE *f = fopen(path, "w");
    if (!f) return -1;
    fprintf(f, "agent_id=%s\nstatus=%s\n", agent_id, status);
    fclose(f);
    return 0;
}
```

- [ ] **Step 5: Wire into `src/lib/CMakeLists.txt`**

Add `registration.c` to the `packetsonde_lib` sources, and after the http_client test block:

```cmake
    add_executable(test_registration tests/test_registration.c)
    target_link_libraries(test_registration PRIVATE packetsonde_lib)
    add_test(NAME test_registration COMMAND test_registration)
```

- [ ] **Step 6: Run to verify it passes**

Run: `cd build && cmake .. -DBUILD_TESTING=ON >/dev/null && make test_registration >/dev/null && ctest -R '^test_registration$' --output-on-failure`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add src/lib/registration.h src/lib/registration.c src/lib/tests/test_registration.c src/lib/CMakeLists.txt
git commit -m "Add registration core: /register JSON payload, sha256(file), marker read/write"
```

---

## Task 4: `[central]` config accessors + documentation

**Files:**
- Create: `src/lib/central_config.h`
- Modify: `packaging/packetsonded.toml`

- [ ] **Step 1: Create `src/lib/central_config.h` (thin reader over ps_config)**

```c
#ifndef PS_CENTRAL_CONFIG_H
#define PS_CENTRAL_CONFIG_H
#include "config.h"

struct ps_central_config {
    const char *url;             /* "" if unset -> central disabled */
    const char *agent_id;        /* "" -> use hostname */
    const char *deployment_mode; /* default "host" */
    int verify;                  /* default 1 */
    const char *ca_cert;         /* "" -> system CAs */
    int checkin_seconds;         /* default 60 */
};

static inline struct ps_central_config ps_central_config_from(const struct ps_config *c) {
    struct ps_central_config cc;
    cc.url             = ps_config_get(c, "central", "url");
    cc.agent_id        = ps_config_get(c, "central", "agent_id");
    cc.deployment_mode = ps_config_get(c, "central", "deployment_mode");
    if (!cc.deployment_mode || !cc.deployment_mode[0]) cc.deployment_mode = "host";
    cc.verify          = ps_config_get_bool(c, "central", "verify", 1);
    cc.ca_cert         = ps_config_get(c, "central", "ca_cert");
    cc.checkin_seconds = ps_config_get_int(c, "central", "checkin_seconds", 60);
    return cc;
}
#endif
```

- [ ] **Step 2: Document the block in `packaging/packetsonded.toml`**

Append:

```toml
# ---- central management (rna-packetsonde) ----------------------------
# When url is set, the agent enrolls with central on first boot and checks
# in periodically. http:// is fine for dev; use https:// + verify in prod.
[central]
url             = ""            # e.g. https://central.example:8700  (empty = disabled)
agent_id        = ""            # empty -> hostname
deployment_mode = "host"        # host | proxy | trunk | bridge
verify          = "1"           # 0 to skip TLS verify (dev / self-signed)
ca_cert         = ""            # optional internal CA pin
checkin_seconds = "60"
```

- [ ] **Step 3: Build (header-only; ensure it compiles where included later)**

Run: `cd build && make packetsonde_lib >/dev/null 2>&1 && echo OK`
Expected: `OK` (no consumer yet; full use lands in Task 5).

- [ ] **Step 4: Commit**

```bash
git add src/lib/central_config.h packaging/packetsonded.toml
git commit -m "Add [central] config accessors + document the block in packetsonded.toml"
```

---

## Task 5: `ps_register` orchestration

**Files:**
- Modify: `src/lib/registration.c`, `src/lib/registration.h` (already declares it)
- Test: `src/lib/tests/test_registration.c` (extend — marker-skip path, no network)

- [ ] **Step 1: Add the failing test (idempotent skip without network)**

```c
/* append to src/lib/tests/test_registration.c, and call from main() */
#include "config.h"
static void test_register_skips_when_marked(void) {
    /* No [central].url -> ps_register must NOT attempt network, returns LOCAL_ERR. */
    struct ps_config cfg; ps_config_parse_string(&cfg, "[keys]\ndir=/tmp\n");
    enum ps_reg_result r = ps_register(&cfg, "direct", 0);
    assert(r == PS_REG_LOCAL_ERR);   /* url unset -> nothing to do */
    ps_config_free(&cfg);
}
```
Add `test_register_skips_when_marked();` to `main()`.

- [ ] **Step 2: Run to verify it fails**

Run: `cd build && make test_registration 2>&1 | tail -5`
Expected: FAIL — `ps_register` undefined (link error).

- [ ] **Step 3: Implement `ps_register` in `src/lib/registration.c`**

Add includes + the function:

```c
#include "central_config.h"
#include "http_client.h"
#include "keystore.h"
#include <unistd.h>
#include <limits.h>

#define PS_REG_MARKER "/etc/packetsonded/registered"

static void self_exe_path(char *out, size_t cap) {
    ssize_t n = readlink("/proc/self/exe", out, cap - 1);
    if (n > 0) { out[n] = 0; return; }
    snprintf(out, cap, "%s", "/usr/local/bin/packetsonded");  /* fallback */
}

static void primary_ipv4(char *out, size_t cap);  /* defined below or reuse discovery helper */

enum ps_reg_result ps_register(const struct ps_config *cfg,
                               const char *provenance, int force) {
    struct ps_central_config cc = ps_central_config_from(cfg);
    if (!cc.url || !cc.url[0]) return PS_REG_LOCAL_ERR;   /* central disabled */

    char marker_id[128];
    if (!force && ps_reg_marker_read(PS_REG_MARKER, marker_id, sizeof marker_id) == 0)
        return PS_REG_ALREADY;

    /* identity: load or generate the keystore 'agent' key */
    const char *keydir = ps_config_get(cfg, "keys", "dir");
    if (!keydir || !keydir[0]) keydir = "/etc/packetsonded/keys";
    struct ps_keypair kp;
    if (ps_keystore_load(keydir, "agent", &kp) != 0) {
        if (ps_keystore_generate(&kp) != 0) return PS_REG_LOCAL_ERR;
        if (ps_keystore_save(keydir, "agent", &kp) != 0) return PS_REG_LOCAL_ERR;
    }

    char exe[PATH_MAX]; self_exe_path(exe, sizeof exe);
    char checksum[65];
    if (ps_sha256_file(exe, checksum) != 0) return PS_REG_LOCAL_ERR;

    char host[256];
    const char *agent_id = (cc.agent_id && cc.agent_id[0]) ? cc.agent_id
                          : (gethostname(host, sizeof host) == 0 ? host : "unknown");

    char ip[64]; primary_ipv4(ip, sizeof ip);

    char payload[1024];
    struct ps_reg_input in = { agent_id, kp.pubkey, checksum,
                               cc.deployment_mode, provenance, ip };
    if (ps_reg_build_payload(payload, sizeof payload, &in) < 0) return PS_REG_LOCAL_ERR;

    char url[640];
    snprintf(url, sizeof url, "%s/api/v1/packetsonde/register", cc.url);
    struct ps_http_opts opts = { cc.verify, cc.ca_cert, cc.checkin_seconds > 0 ? 10 : 10 };
    int status = 0; char resp[2048];
    if (ps_http_request("POST", url, payload, &opts, &status, resp, sizeof resp) != 0)
        return PS_REG_HTTP_ERR;
    if (status != 201 && status != 200 && status != 409) return PS_REG_HTTP_ERR;

    ps_reg_marker_write(PS_REG_MARKER, agent_id, status == 409 ? "exists" : "pending");
    return PS_REG_OK;
}

/* Minimal primary-v4 detection: UDP-connect a public-ish addr, read local sockname.
 * (Mirrors the agent's discovery "auto" detection; no packets are sent.) */
#include <sys/socket.h>
#include <arpa/inet.h>
static void primary_ipv4(char *out, size_t cap) {
    out[0] = 0;
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return;
    struct sockaddr_in to = {0}; to.sin_family = AF_INET; to.sin_port = htons(53);
    inet_pton(AF_INET, "10.255.255.255", &to.sin_addr);
    if (connect(s, (struct sockaddr*)&to, sizeof to) == 0) {
        struct sockaddr_in me; socklen_t ml = sizeof me;
        if (getsockname(s, (struct sockaddr*)&me, &ml) == 0)
            inet_ntop(AF_INET, &me.sin_addr, out, cap);
    }
    close(s);
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `cd build && make test_registration >/dev/null && ctest -R '^test_registration$' --output-on-failure`
Expected: PASS (the new test exercises the `url`-unset early return; no network).

- [ ] **Step 5: Commit**

```bash
git add src/lib/registration.c src/lib/tests/test_registration.c
git commit -m "Implement ps_register: identity, self-checksum, agent_id/ip, POST /register, marker"
```

---

## Task 6: `packetsonde register` CLI verb

**Files:**
- Create: `src/cli/verbs/register.c`
- Modify: `src/cli/verbs.c` (add to the verb registry)

- [ ] **Step 1: Create `src/cli/verbs/register.c`**

```c
#include "../verbs.h"
#include "config.h"
#include "registration.h"
#include <stdio.h>
#include <string.h>
#include <getopt.h>

int ps_verb_register_run(int argc, char **argv, const struct ps_args *opts) {
    (void)opts;
    const char *cfg_path = "/etc/packetsonded/packetsonded.toml";
    const char *provenance = "salt";
    int force = 0;
    static struct option lo[] = {
        {"config", required_argument, 0, 'c'},
        {"provenance", required_argument, 0, 'p'},
        {"force", no_argument, 0, 'f'},
        {0,0,0,0}
    };
    int c;
    while ((c = getopt_long(argc, argv, "c:p:f", lo, NULL)) != -1) {
        if (c == 'c') cfg_path = optarg;
        else if (c == 'p') provenance = optarg;
        else if (c == 'f') force = 1;
    }
    struct ps_config cfg;
    if (ps_config_parse_file(&cfg, cfg_path) != 0) {
        fprintf(stderr, "register: cannot read config %s\n", cfg_path);
        return 1;
    }
    enum ps_reg_result r = ps_register(&cfg, provenance, force);
    ps_config_free(&cfg);
    switch (r) {
        case PS_REG_OK:      printf("registered (pending validation)\n"); return 0;
        case PS_REG_ALREADY: printf("already registered\n"); return 0;
        case PS_REG_HTTP_ERR: fprintf(stderr, "register: central unreachable / rejected\n"); return 2;
        default:             fprintf(stderr, "register: local error (central url unset?)\n"); return 1;
    }
}
```

- [ ] **Step 2: Register the verb in `src/cli/verbs.c`**

Add the extern + a registry entry. Find the verb table (array of `struct ps_verb`) and add:

```c
extern int ps_verb_register_run(int argc, char **argv, const struct ps_args *opts);
/* ... in the table: */
    { "register", ps_verb_register_run, "Enroll this host with central management" },
```

- [ ] **Step 3: Wire `register.c` into the CLI build**

In `src/cli/CMakeLists.txt`, add `verbs/register.c` to the `packetsonde` (CLI) target's source list (next to the other `verbs/*.c`).

- [ ] **Step 4: Build + smoke-test the verb registers**

Run: `cd build && make packetsonde >/dev/null 2>&1 && ./src/cli/packetsonde help 2>&1 | grep register`
Expected: the `register` verb appears in the verb list.

- [ ] **Step 5: Commit**

```bash
git add src/cli/verbs/register.c src/cli/verbs.c src/cli/CMakeLists.txt
git commit -m "Add `packetsonde register` verb (provenance + force flags)"
```

---

## Task 7: Daemon self-enroll + checkin loop

**Files:**
- Create: `src/agent/src/central_checkin.h`, `src/agent/src/central_checkin.c`
- Modify: `src/agent/src/main.c`

- [ ] **Step 1: Create `src/agent/src/central_checkin.h`**

```c
#ifndef PS_CENTRAL_CHECKIN_H
#define PS_CENTRAL_CHECKIN_H
#include "config.h"
/* One checkin POST. Returns 0 on 200. uptime_seconds from caller. */
int ps_central_checkin_once(const struct ps_config *cfg, long uptime_seconds);
#endif
```

- [ ] **Step 2: Create `src/agent/src/central_checkin.c`**

```c
#include "central_checkin.h"
#include "central_config.h"
#include "http_client.h"
#include "json.h"
#include "build_config.h"   /* PS_AGENT_VERSION */
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int ps_central_checkin_once(const struct ps_config *cfg, long uptime_seconds) {
    struct ps_central_config cc = ps_central_config_from(cfg);
    if (!cc.url || !cc.url[0]) return -1;

    char host[256];
    const char *agent_id = (cc.agent_id && cc.agent_id[0]) ? cc.agent_id
                          : (gethostname(host, sizeof host) == 0 ? host : "unknown");

    char body[512]; struct ps_json j; ps_json_init(&j, body, sizeof body);
    ps_json_object_begin(&j);
    ps_json_key_string(&j, "agent_id", agent_id);
    ps_json_key_int(&j, "uptime_seconds", uptime_seconds);
    ps_json_key_string(&j, "config_version", "none");
    ps_json_key_string(&j, "agent_version", PS_AGENT_VERSION);
    ps_json_key_string(&j, "key_rotation_status", "none");
    ps_json_object_end(&j);
    if (ps_json_finish(&j) != 0) return -1;

    char url[640]; snprintf(url, sizeof url, "%s/api/v1/packetsonde/checkin", cc.url);
    struct ps_http_opts opts = { cc.verify, cc.ca_cert, 10 };
    int status = 0; char resp[1024];
    if (ps_http_request("POST", url, body, &opts, &status, resp, sizeof resp) != 0) return -1;
    return status == 200 ? 0 : -1;
}
```

> If `build_config.h` has no `PS_AGENT_VERSION`, add `#define PS_AGENT_VERSION "@PROJECT_VERSION@"` to `src/agent/src/build_config.h.in` (it is configured by CMake — check the existing variables there and follow the same `@VAR@` substitution style).

- [ ] **Step 3: Hook self-enroll + checkin into `src/agent/src/main.c`**

After config is loaded and the daemon's main setup completes (before/at the start of the main service loop), add:

```c
#include "registration.h"
#include "central_checkin.h"
#include "central_config.h"
/* ... after cfg is loaded: */
{
    struct ps_central_config cc = ps_central_config_from(&cfg);
    if (cc.url && cc.url[0]) {
        enum ps_reg_result r = ps_register(&cfg, "direct", 0);
        /* non-fatal: log and continue regardless */
        ps_log(PS_LOG_INFO, "central: enroll result=%d", (int)r);
    }
}
```

And in the daemon's periodic-work path (wherever the agent already does timed work, e.g. its main `select`/sleep loop), add a checkin every `cc.checkin_seconds`:

```c
static time_t last_checkin = 0;
time_t now = time(NULL);
struct ps_central_config cc = ps_central_config_from(&cfg);
if (cc.url && cc.url[0] && now - last_checkin >= cc.checkin_seconds) {
    ps_central_checkin_once(&cfg, now - start_time);
    last_checkin = now;
}
```

(Use the agent's existing logger macro — match whatever `ps_log`/`log_info` symbol `main.c` already uses; `start_time` is the daemon start timestamp, captured at startup.)

- [ ] **Step 4: Wire `central_checkin.c` into the agent build**

In `src/agent/CMakeLists.txt` (or wherever the `packetsonded` target lists sources), add `src/central_checkin.c`. Ensure the agent target links `packetsonde_lib` (for `http_client`/`registration`/`json`); if it doesn't already, add `target_link_libraries(packetsonded PRIVATE packetsonde_lib)`.

- [ ] **Step 5: Build the daemon**

Run: `cd build && make packetsonded 2>&1 | tail -8`
Expected: compiles + links cleanly.

- [ ] **Step 6: Commit**

```bash
git add src/agent/src/central_checkin.h src/agent/src/central_checkin.c src/agent/src/main.c src/agent/CMakeLists.txt
git commit -m "Daemon: self-enroll on boot + periodic central checkin"
```

---

## Task 8: Integration test — register against live psdev

**Files:**
- Create: `scripts/test-register-psdev.sh`

- [ ] **Step 1: Create `scripts/test-register-psdev.sh`**

```bash
#!/bin/bash
# Integration: register a throwaway agent against the live psdev central,
# verify a pending ps_agents doc appears, then clean up.
# Usage: scripts/test-register-psdev.sh http://10.0.1.10:8700
set -e
CENTRAL="${1:?usage: $0 <central-url>}"
AID="test-agent-$(openssl rand -hex 6)"
TMP=$(mktemp -d)
cat > "$TMP/packetsonded.toml" <<EOF
[keys]
dir = "$TMP/keys"
[central]
url = "$CENTRAL"
agent_id = "$AID"
deployment_mode = "host"
verify = "0"
EOF
mkdir -p "$TMP/keys"

echo "registering $AID ..."
./build/src/cli/packetsonde register --config "$TMP/packetsonded.toml" --provenance direct
echo "registered; verify in psdev: GET /api/v1/packetsonde/agents?status=pending should include $AID"
echo "agent_id=$AID  (clean up the pending ps_agents doc afterward)"
rm -rf "$TMP"
```

- [ ] **Step 2: Run it (manual, requires reachable psdev)**

Run: `chmod +x scripts/test-register-psdev.sh && ./scripts/test-register-psdev.sh http://10.0.1.10:8700`
Expected: prints "registered (pending validation)"; the `$AID` then appears in psdev's admin Agents list as `pending`. (Validate it → run a checkin from the same config to confirm it shows online.)

- [ ] **Step 3: Commit**

```bash
git add scripts/test-register-psdev.sh
git commit -m "Add psdev registration integration smoke-test script"
```

---

## Task 9: Deployment — `packetsonded-bootstrap` + rna-salt state

**Files:**
- Modify: `packaging/bootstrap` (→ `packetsonded-bootstrap`)
- Create (in the **rna-salt** repo): `salt/packetsonde/init.sls`, `salt/packetsonde/packetsonded.toml.jinja`, `salt/packetsonde/pillar.example.sls`

- [ ] **Step 1: Extend `packaging/bootstrap` into `packetsonded-bootstrap`**

```bash
#!/bin/bash
# packetsonded-bootstrap: write [central] config, ensure identity, self-enroll.
# Usage: packetsonded-bootstrap --central URL --mode host [--agent-id N]
#        [--ca-cert FILE | --insecure] [--config /etc/packetsonded/packetsonded.toml]
set -e
CONF="/etc/packetsonded/packetsonded.toml"; MODE="host"; AID=""; CENTRAL=""
VERIFY="1"; CA=""
while [ $# -gt 0 ]; do case "$1" in
  --central) CENTRAL="$2"; shift 2;;
  --mode) MODE="$2"; shift 2;;
  --agent-id) AID="$2"; shift 2;;
  --ca-cert) CA="$2"; shift 2;;
  --insecure) VERIFY="0"; shift;;
  --config) CONF="$2"; shift 2;;
  *) echo "unknown arg: $1" >&2; exit 2;;
esac; done
[ -n "$CENTRAL" ] || { echo "--central URL required" >&2; exit 2; }

# Append/replace the [central] block (idempotent: strip any existing one first).
mkdir -p "$(dirname "$CONF")"
[ -f "$CONF" ] || touch "$CONF"
awk 'BEGIN{s=0} /^\[central\]/{s=1;next} /^\[/{s=0} s==0{print}' "$CONF" > "$CONF.tmp"
cat >> "$CONF.tmp" <<EOF
[central]
url             = "$CENTRAL"
agent_id        = "$AID"
deployment_mode = "$MODE"
verify          = "$VERIFY"
ca_cert         = "$CA"
checkin_seconds = "60"
EOF
mv "$CONF.tmp" "$CONF"

# Enroll (keygen happens inside ps_register if needed).
packetsonde register --config "$CONF" --provenance direct || true
echo "bootstrap complete: [central] written, enrollment attempted (pending validation)."
echo "enable the service: systemctl enable --now packetsonded   (or platform equivalent)"
```

- [ ] **Step 2: Create the rna-salt state `salt/packetsonde/init.sls`** (in the rna-salt repo)

```yaml
packetsonde-agent-pkg:
  pkg.installed:
    - name: packetsonde-agent

packetsonded-config:
  file.managed:
    - name: /etc/packetsonded/packetsonded.toml
    - source: salt://packetsonde/packetsonded.toml.jinja
    - template: jinja
    - require:
      - pkg: packetsonde-agent-pkg

packetsonde-register:
  cmd.run:
    - name: packetsonde register --config /etc/packetsonded/packetsonded.toml --provenance salt
    - unless: test -f /etc/packetsonded/registered
    - require:
      - file: packetsonded-config

packetsonded-service:
  service.running:
    - name: packetsonded
    - enable: true
    - watch:
      - file: packetsonded-config
```

- [ ] **Step 3: Create `salt/packetsonde/packetsonded.toml.jinja`**

```jinja
[keys]
dir = "/etc/packetsonded/keys"

[central]
url             = "{{ salt['pillar.get']('packetsonde:central_url', '') }}"
agent_id        = "{{ grains['id'] }}"
deployment_mode = "{{ salt['pillar.get']('packetsonde:deployment_mode', 'host') }}"
verify          = "{{ salt['pillar.get']('packetsonde:verify', '1') }}"
ca_cert         = "{{ salt['pillar.get']('packetsonde:ca_cert', '') }}"
checkin_seconds = "60"
```

- [ ] **Step 4: Create `salt/packetsonde/pillar.example.sls`**

```yaml
packetsonde:
  central_url: https://central.example:8700
  deployment_mode: host
  verify: "1"
  ca_cert: ""
```

- [ ] **Step 5: Commit (two repos)**

```bash
# packetsonde repo:
git add packaging/bootstrap
git commit -m "Extend bootstrap into packetsonded-bootstrap (writes [central], self-enrolls)"
# rna-salt repo:
git add salt/packetsonde/
git commit -m "Add packetsonde agent salt state + config template + example pillar"
```

---

## Self-Review

**Spec coverage:**
- §3.1 http_client (OpenSSL, verify/ca_cert, http for dev) → Tasks 1, 2 ✓
- §3.2 registration routine (keygen, sha256(self), payload, POST, marker, idempotent) → Tasks 3, 5 ✓
- §3.3 `packetsonde register` verb (provenance/force) → Task 6 ✓
- §3.4 daemon self-enroll on boot → Task 7 ✓
- §3.5 checkin loop → Task 7 ✓
- §4 `[central]` config block → Task 4 ✓
- §5.1 packetsonded-bootstrap, §5.2 rna-salt state → Task 9 ✓
- §6 one Ed25519 keystore identity → Task 5 (loads/gens keystore `agent`) ✓
- §8 testing (unit + live-psdev integration) → Tasks 1,3,5 (unit) + 8 (integration) ✓
- §9 reporting/config-fetch/rotation → deferred, not in plan (correct).

**Placeholder scan:** No TBD/TODO. Two explicit "match the existing symbol" notes (Task 7: the agent's logger macro + `start_time`; `PS_AGENT_VERSION` in build_config) are integration points into unread daemon code, not placeholders — each gives the exact thing to look for and a concrete fallback.

**Type/name consistency:** `ps_url`/`ps_http_opts`/`ps_http_request`/`ps_url_parse`/`ps_http_build_request`/`ps_http_parse_response` (Tasks 1,2,5,7); `ps_reg_input`/`ps_reg_build_payload`/`ps_sha256_file`/`ps_reg_marker_read|write`/`ps_register`/`enum ps_reg_result` (Tasks 3,5,6); `ps_central_config_from` (Tasks 4,5,7); `ps_central_checkin_once` (Task 7) — consistent. Central routes/payloads match the shipped rna-packetsonde endpoints.
