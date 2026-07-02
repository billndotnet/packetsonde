/*
 * network_listener.c -- accepts inbound mTLS sessions from `packetsonde
 * --via <agent>`, dispatches audit requests to the local `packetsonde`
 * binary as a subprocess, and streams its JSONL findings back as
 * agent_proto 'finding' frames.
 *
 * Per the brainstorm:
 *   - TLS 1.3 with Ed25519 self-signed cert (agent_transport.c)
 *   - mTLS, peer pubkey fingerprint must appear in PS_AGENT_AUTHORIZED_DIR
 *   - length-prefixed JSON inside the tunnel (agent_proto.c)
 *   - one connection per audit run, pthread per connection
 *   - cap on concurrent sessions (default 64, PS_AGENT_MAX_CLIENTS)
 *
 * Configuration (env, defaults shown):
 *   PS_AGENT_LISTEN_ENABLED      "0"        opt-in; default off
 *   PS_AGENT_LISTEN_ADDR         "0.0.0.0"  bind address
 *   PS_AGENT_LISTEN_PORT         "8442"
 *   PS_KEY_DIR                   ~/.config/packetsonde/keys
 *   PS_AGENT_LISTEN_KEY          "agent"    keypair name in PS_KEY_DIR
 *   PS_AGENT_AUTHORIZED_DIR      "$PS_KEY_DIR/authorized"
 *   PS_AGENT_MAX_CLIENTS         "64"
 *   PS_PACKETSONDE_BIN           "packetsonde"
 */

#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "packetsonde/module_api.h"
#include "agent_proto.h"
#include "agent_transport.h"
#include "keystore.h"
#include "recipe.h"
#include "relay_attest.h"
#include "http_client.h"
#include "log.h"

#define MAX_AUTHORIZED 64
/* Mirrors PS_ARGS_MAX_VIA_HOPS in the CLI: longest --via chain we accept
 * in a single forwarded request. Defense-in-depth bound on argv growth
 * and recursion depth across the agent fleet. */
#define PS_NL_MAX_VIA_HOPS 8

/* Bulk probe support (e.g.  over agent_proto): allow a large
 * target list. Ceiling covers a /22 (1024 hosts) + kind + a couple of flags;
 * the client chunks anything larger. argbuf holds that many IPv6-length
 * tokens. Per-connection thread stack is the glibc 8 MB default, so these
 * auto buffers are safe. */
#define PS_NL_MAX_ARGS  1056
#define PS_NL_ARGBUF_SZ (64 * 1024)

struct nl_state {
    int                listen_fd;
    struct ps_at_ctx   tctx;
    struct ps_keypair  agent_kp;
    uint8_t            authorized[MAX_AUTHORIZED][32];
    size_t             authorized_n;
    pthread_t          accept_tid;
    int                running;
    atomic_int         stop;
    atomic_int         active_clients;
    int                max_clients;
    char               packetsonde_bin[256];
};

static struct nl_state *g_state = NULL; /* module userdata mirror */

/* ---- authorized-keys discovery ----------------------------------- */

static void load_authorized(struct nl_state *st, const char *dir) {
    DIR *d = opendir(dir);
    if (!d) {
        ps_info("network_listener: authorized dir '%s' missing -- no clients can connect", dir);
        return;
    }
    struct dirent *de;
    while ((de = readdir(d)) != NULL && st->authorized_n < MAX_AUTHORIZED) {
        size_t n = strlen(de->d_name);
        if (n < 5 || strcmp(de->d_name + n - 4, ".pub") != 0) continue;
        char p[1100]; snprintf(p, sizeof(p), "%s/%s", dir, de->d_name);
        FILE *f = fopen(p, "rb");
        if (!f) continue;
        if (fread(st->authorized[st->authorized_n], 1,
                  PS_KEYSTORE_PUBKEY_SIZE, f) == PS_KEYSTORE_PUBKEY_SIZE) {
            st->authorized_n++;
        }
        fclose(f);
    }
    closedir(d);
    ps_info("network_listener: %zu authorized client pubkey(s) loaded from %s",
            st->authorized_n, dir);
}

static int is_authorized(struct nl_state *st, SSL *ssl) {
    char fpr[PS_KEYSTORE_FPR_HEX_SIZE];
    if (ps_at_peer_fingerprint(ssl, fpr, sizeof(fpr)) != 0) return 0;
    /* Constant-time-ish scan: walk all entries even after a match so a
     * timing oracle can't enumerate the authorized list. */
    int matched = 0;
    for (size_t i = 0; i < st->authorized_n; i++) {
        char expected[PS_KEYSTORE_FPR_HEX_SIZE];
        ps_keystore_fingerprint(st->authorized[i], expected);
        if (strcmp(fpr, expected) == 0) matched = 1;
    }
    if (matched) return 1;
    return 0;
}

/* ---- subprocess driver ------------------------------------------- */

/* Read the audit request frame and pull out kind + args[]. Returns 0 on
 * success, -1 on malformed. Caller-provided argv[] is filled with
 * pointers into argbuf (a private scratch buffer). */
static int parse_audit_request(const uint8_t *frame, size_t len,
                               char *argbuf, size_t argbuf_sz,
                               char **argv, int argv_cap, int *argc_out,
                               const char **via_chain, int via_cap,
                               int *via_count_out) {
    /* The frame shape we emit on the CLI side:
     *   {"type":"audit","kind":"<k>","args":["a","b",...],
     *    "via_chain":["host1","host2",...]?}
     * Conservative scanner: find each keyed array/string in turn. */
    const uint8_t *p = frame;
    const uint8_t *end = frame + len;
    const char *kind_lit = "\"kind\"";
    const char *args_lit = "\"args\"";
    const char *via_lit  = "\"via_chain\"";

    const uint8_t *kp = NULL, *ap = NULL, *vp = NULL;
    for (const uint8_t *s = p; s + 6 <= end; s++) {
        if (!kp && memcmp(s, kind_lit, 6) == 0) kp = s + 6;
        if (!ap && memcmp(s, args_lit, 6) == 0) ap = s + 6;
        if (!vp && s + 11 <= end && memcmp(s, via_lit, 11) == 0) vp = s + 11;
        if (kp && ap && vp) break;
    }
    if (!kp) return -1;
    while (kp < end && (*kp == ' ' || *kp == ':' || *kp == '\t')) kp++;
    if (kp >= end || *kp != '"') return -1;
    const uint8_t *kv = kp + 1;
    const uint8_t *kve = kv;
    while (kve < end && *kve != '"') {
        if (*kve == '\\' && kve + 1 < end) kve += 2;
        else kve++;
    }
    if (kve >= end) return -1;
    size_t klen = (size_t)(kve - kv);
    if (klen + 1 > argbuf_sz) return -1;
    memcpy(argbuf, kv, klen); argbuf[klen] = '\0';
    int argc = 0;
    argv[argc++] = argbuf;
    size_t off = klen + 1;

    if (ap) {
        while (ap < end && (*ap == ' ' || *ap == ':' || *ap == '\t')) ap++;
        if (ap < end && *ap == '[') {
            ap++;
            while (ap < end && argc < argv_cap) {
                while (ap < end && (*ap == ' ' || *ap == ',' || *ap == '\t')) ap++;
                if (ap >= end || *ap == ']') break;
                if (*ap != '"') return -1;
                ap++;
                const uint8_t *avs = ap;
                while (ap < end && *ap != '"') {
                    if (*ap == '\\' && ap + 1 < end) ap += 2;
                    else ap++;
                }
                if (ap >= end) return -1;
                size_t alen = (size_t)(ap - avs);
                if (off + alen + 1 > argbuf_sz) return -1;
                memcpy(argbuf + off, avs, alen);
                argbuf[off + alen] = '\0';
                argv[argc++] = argbuf + off;
                off += alen + 1;
                ap++;
            }
        }
    }
    *argc_out = argc;

    /* via_chain (optional). Walks an array of strings. Each entry has to
     * be a safe hostname-ish token; we use the same arg_is_safe check
     * below so the runner can't be tricked into building --via with
     * shell-meta payloads. */
    int via_count = 0;
    if (vp && via_chain && via_cap > 0) {
        while (vp < end && (*vp == ' ' || *vp == ':' || *vp == '\t')) vp++;
        if (vp < end && *vp == '[') {
            vp++;
            while (vp < end && via_count < via_cap) {
                while (vp < end && (*vp == ' ' || *vp == ',' || *vp == '\t')) vp++;
                if (vp >= end || *vp == ']') break;
                if (*vp != '"') return -1;
                vp++;
                const uint8_t *avs = vp;
                while (vp < end && *vp != '"') {
                    if (*vp == '\\' && vp + 1 < end) vp += 2;
                    else vp++;
                }
                if (vp >= end) return -1;
                size_t alen = (size_t)(vp - avs);
                if (off + alen + 1 > argbuf_sz) return -1;
                memcpy(argbuf + off, avs, alen);
                argbuf[off + alen] = '\0';
                via_chain[via_count++] = argbuf + off;
                off += alen + 1;
                vp++;
            }
        }
    }
    if (via_count_out) *via_count_out = via_count;
    return 0;
}

/* Drive the subprocess: build argv, fork, exec packetsonde, stream stdout
 * line by line to the SSL session as finding frames. */
/* Audit kinds that the subprocess is allowed to invoke. Matches the
 * built-in module list in src/cli/verbs/audit.c. Centralised here so a
 * malicious authorized client cannot inject arbitrary verbs or shell
 * tokens via the JSON 'kind' field -- see C-2 in the security review.
 *
 * If you add a new audit module to the CLI, also add it here. The
 * test_via_e2e bash test exercises 'ssh' so the most-trafficked path
 * stays covered. */
static const char *AUDIT_KIND_ALLOWLIST[] = {
    "tls", "dns", "http", "ssh", "smb", "telnet", "ftp", "redis",
    "ntp", "memcached", "elasticsearch", "smtp", "mysql", "postgresql",
    "ldap", "imap", "pop3", "snmp", "rdp", "mssql", "kafka", "vnc",
    "haproxy", "proxmox", "nginx", "opnsense", NULL
};

/* Probe kinds the subprocess is allowed to invoke under the `probe` verb.
 * Same threat model as AUDIT_KIND_ALLOWLIST: an authorized client must not
 * be able to inject arbitrary verbs/tokens via the JSON 'kind' field. */
static const char *PROBE_KIND_ALLOWLIST[] = { "tcp", "udp", "icmp", "sweep", "traceroute", NULL };

/* Validate `kind` against the allowlist matching the request verb. */
static int kind_is_allowed(const char *kind, bool is_probe) {
    if (!kind || !*kind) return 0;
    const char **allow = is_probe ? PROBE_KIND_ALLOWLIST : AUDIT_KIND_ALLOWLIST;
    for (const char **p = allow; *p; p++) {
        if (strcmp(*p, kind) == 0) return 1;
    }
    return 0;
}

/* Reject any argument that contains a byte that could change shell or
 * exec semantics. We're using execvp (no shell), so this is mostly
 * about catching characters that downstream parsers in the audit
 * modules might mis-handle. Conservative: alphanumeric + a small
 * punctuation set that covers host:port, paths, CIDRs, ports lists. */
static int arg_is_safe(const char *s) {
    for (const char *p = s; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if (c >= 'a' && c <= 'z') continue;
        if (c >= 'A' && c <= 'Z') continue;
        if (c >= '0' && c <= '9') continue;
        if (c == '.' || c == ':' || c == '-' || c == '_' ||
            c == '/' || c == ',' || c == '@' || c == '=') continue;
        return 0;
    }
    return 1;
}

static void run_subprocess(struct nl_state *st,
                           bool is_probe,
                           const char *audit_kind,
                           char **audit_argv, int audit_argc,
                           const char **via_chain, int via_count,
                           const struct ps_ap_io *io) {
    int pfd[2];
    if (pipe(pfd) != 0) return;

    pid_t pid = fork();
    if (pid < 0) { close(pfd[0]); close(pfd[1]); return; }

    if (pid == 0) {
        /* child: stdout -> pipe write, stderr -> /dev/null */
        dup2(pfd[1], 1);
        int n = open("/dev/null", O_WRONLY); if (n >= 0) { dup2(n, 2); close(n); }
        close(pfd[0]); close(pfd[1]);
        /* argv: packetsonde --jsonl [--via X]... <verb> <kind> <args...> NULL
         *
         * verb is "probe" or "audit" depending on the request type.
         *
         * Multi-hop: each entry in via_chain adds a `--via NAME` pair so
         * the subprocess opens another --via session to the next hop.
         * The receiving agent there sees one fewer entry, and so on. */
        const char *verb = is_probe ? "probe" : "audit";
        const char *argv[PS_NL_MAX_ARGS + 24] = {0};
        int i = 0;
        argv[i++] = st->packetsonde_bin;
        argv[i++] = "--jsonl";
        for (int v = 0; v < via_count && i + 2 < (int)(sizeof(argv)/sizeof(argv[0])) - 1; v++) {
            argv[i++] = "--via";
            argv[i++] = via_chain[v];
        }
        argv[i++] = verb;
        argv[i++] = audit_kind;
        for (int j = 1; j < audit_argc && i < (int)(sizeof(argv)/sizeof(argv[0])) - 1; j++) argv[i++] = audit_argv[j];
        argv[i] = NULL;
        execvp(argv[0], (char *const *)argv);
        _exit(127);
    }
    /* parent */
    close(pfd[1]);

    /* Read stdout line by line; each complete line becomes a finding frame. */
    char buf[16384];
    size_t bl = 0;
    for (;;) {
        ssize_t r = read(pfd[0], buf + bl, sizeof(buf) - bl - 1);
        if (r <= 0) break;
        bl += (size_t)r;
        size_t scan_from = 0;
        while (scan_from < bl) {
            char *nl = memchr(buf + scan_from, '\n', bl - scan_from);
            if (!nl) break;
            size_t line_len = (size_t)(nl - (buf + scan_from));
            if (line_len > 0 && buf[scan_from] == '{') {
                /* Wrap in a "finding" frame: {"type":"finding","payload":<line>} */
                char frame[20000];
                int fn = snprintf(frame, sizeof(frame),
                                  "{\"type\":\"finding\",\"payload\":%.*s}",
                                  (int)line_len, buf + scan_from);
                if (fn > 0 && (size_t)fn < sizeof(frame)) {
                    if (ps_ap_write_frame(io, frame, (size_t)fn) != PS_AP_OK)
                        goto done;
                }
            }
            scan_from += line_len + 1;
        }
        /* shift remainder to front */
        if (scan_from < bl) memmove(buf, buf + scan_from, bl - scan_from);
        bl -= scan_from;
        if (bl == sizeof(buf) - 1) bl = 0; /* avoid wedging on a pathological line */
    }

done:
    close(pfd[0]);
    int status = 0;
    waitpid(pid, &status, 0);

    /* Send bye frame. */
    char bye[128];
    int bn = snprintf(bye, sizeof(bye),
                      "{\"type\":\"bye\",\"status\":%d}",
                      WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    if (bn > 0) ps_ap_write_frame(io, bye, (size_t)bn);
}

/* ---- per-session thread ----------------------------------------- */

struct session_args {
    struct nl_state *st;
    SSL             *ssl;
};

/* Relay role: forward an ingest frame's envelopes to central, appending this
 * relay's signed attestation to each. peer_id = connecting peer (received_from).
 * Writes an ack JSON into `ack`; returns the accepted count central reported.
 * NOTE: appends a fresh relay_path per envelope — correct for single-hop; merging
 * into a pre-existing relay_path (multi-hop) is a follow-up. */
static int handle_ingest(struct nl_state *st, const char *peer_id,
                         const uint8_t *frame, size_t len, char *ack, size_t ack_cap) {
    (void)len;
    const char *allow = getenv("PS_RELAY_ALLOW_SOURCES");
    if (!allow || !peer_id[0] || !strstr(allow, peer_id)) {
        snprintf(ack, ack_cap,
                 "{\"type\":\"ack\",\"accepted\":0,\"rejected\":0,\"detail\":\"source not allowed\"}");
        return 0;
    }
    const char *p = strstr((const char *)frame, "\"envelopes\":");
    const char *arr = p ? strchr(p, '[') : NULL;
    if (!arr) {
        snprintf(ack, ack_cap,
                 "{\"type\":\"ack\",\"accepted\":0,\"rejected\":0,\"detail\":\"no envelopes\"}");
        return 0;
    }

    char self_id[256];
    const char *cid = getenv("PS_CENTRAL_AGENT_ID");
    if (cid && cid[0]) snprintf(self_id, sizeof self_id, "%s", cid);
    else if (gethostname(self_id, sizeof self_id) != 0) snprintf(self_id, sizeof self_id, "relay");

    static char fwd[262144];
    size_t fo = 0;
    fo += (size_t)snprintf(fwd + fo, sizeof fwd - fo, "{\"envelopes\":[");
    int depth = 0; const char *obj_start = NULL; int first = 1;
    for (const char *c = arr; *c; c++) {
        if (*c == '{') { if (depth == 0) obj_start = c; depth++; }
        else if (*c == '}') {
            depth--;
            if (depth == 0 && obj_start) {
                size_t objlen = (size_t)(c - obj_start) + 1;
                char obj[20000];
                if (objlen < sizeof obj) {
                    memcpy(obj, obj_start, objlen); obj[objlen] = 0;
                    char sig[128] = "";
                    const char *sp = strstr(obj, "\"ed25519_sig\":\"");
                    if (sp) {
                        sp += 15; const char *se = strchr(sp, '"');
                        if (se && (size_t)(se - sp) < sizeof sig) {
                            memcpy(sig, sp, (size_t)(se - sp)); sig[se - sp] = 0;
                        }
                    }
                    char entry[1024];
                    if (ps_relay_attest_entry(&st->agent_kp, self_id, sig, peer_id,
                                              entry, sizeof entry) > 0) {
                        obj[objlen - 1] = 0;  /* drop trailing '}' */
                        fo += (size_t)snprintf(fwd + fo, sizeof fwd - fo,
                                               "%s%s,\"relay_path\":[%s]}",
                                               first ? "" : ",", obj, entry);
                        first = 0;
                    }
                }
                obj_start = NULL;
                if (fo >= sizeof fwd - 64) break;
            }
        } else if (*c == ']' && depth == 0) break;
    }
    fo += (size_t)snprintf(fwd + fo, sizeof fwd - fo, "]}");

    const char *base = getenv("PS_CENTRAL_URL");
    if (!base || !base[0]) {
        snprintf(ack, ack_cap,
                 "{\"type\":\"ack\",\"accepted\":0,\"rejected\":0,\"detail\":\"relay has no central url\"}");
        return 0;
    }
    char url[640]; snprintf(url, sizeof url, "%s/api/v1/packetsonde/events", base);
    char hdr[320]; snprintf(hdr, sizeof hdr, "X-Packetsonde-Relay: %s\r\n", self_id);
    const char *verify = getenv("PS_CENTRAL_VERIFY");
    struct ps_http_opts opts = { (verify && verify[0] == '0') ? 0 : 1,
                                 getenv("PS_CENTRAL_CA_CERT"), 15 };
    int status = 0; char resp[8192]; int accepted = 0;
    if (ps_http_request_h("POST", url, fwd, hdr, &opts, &status, resp, sizeof resp) == 0) {
        const char *a = strstr(resp, "\"accepted\":"); accepted = a ? atoi(a + 11) : 0;
    }
    snprintf(ack, ack_cap, "{\"type\":\"ack\",\"accepted\":%d,\"rejected\":0,\"detail\":\"\"}", accepted);
    return accepted;
}

static void *session_thread(void *arg) {
    struct session_args *sa = arg;
    struct nl_state *st = sa->st;
    SSL *ssl = sa->ssl;
    free(sa);

    if (!is_authorized(st, ssl)) {
        ps_warn("network_listener: rejected client; pubkey not authorized");
        ps_at_close(ssl);
        atomic_fetch_sub(&st->active_clients, 1);
        return NULL;
    }

    struct ps_ap_io io; ps_at_make_io(ssl, &io);

    /* Send our hello. */
    char hello[256];
    char fpr[PS_KEYSTORE_FPR_HEX_SIZE];
    ps_keystore_fingerprint(st->agent_kp.pubkey, fpr);
    int hn = snprintf(hello, sizeof(hello),
                      "{\"type\":\"hello\",\"v\":%d,\"agent_fingerprint\":\"sha256:%s\","
                      "\"max_recipe_schema\":%d}",
                      PS_AGENT_PROTO_VERSION, fpr, PS_RECIPE_SCHEMA_MAX);
    if (hn < 0 || ps_ap_write_frame(&io, hello, (size_t)hn) != PS_AP_OK) goto out;

    /* Expect hello + audit request from client. */
    uint8_t buf[64 * 1024]; size_t blen;
    int saw_hello = 0;
    int dispatched = 0;
    while (!dispatched) {
        if (ps_ap_read_frame(&io, buf, sizeof(buf), &blen) != PS_AP_OK) goto out;
        char type[32];
        if (ps_ap_frame_type(buf, blen, type, sizeof(type)) != 0) continue;
        if (strcmp(type, "hello") == 0) { saw_hello = 1; continue; }
        if (strcmp(type, "ingest") == 0) {
            char peer_id[128] = "";
            ps_at_peer_fingerprint(ssl, peer_id, sizeof peer_id);
            char ack[1024];
            handle_ingest(st, peer_id, buf, blen, ack, sizeof ack);
            ps_ap_write_frame(&io, ack, strlen(ack));
            dispatched = 1;
            continue;
        }
        bool is_probe = strcmp(type, "probe") == 0;
        if (!is_probe && strcmp(type, "audit") != 0) continue;
        if (!saw_hello) {
            const char *e = "{\"type\":\"error\",\"message\":\"request before hello\"}";
            ps_ap_write_frame(&io, e, strlen(e));
            goto out;
        }
        /* Parse + dispatch. The request shape is identical for audit and
         * probe ({type,kind,args[],via_chain[]?}); only the verb differs. */
        char argbuf[PS_NL_ARGBUF_SZ]; char *av[PS_NL_MAX_ARGS] = {0}; int ac = 0;
        const char *via_chain[PS_NL_MAX_VIA_HOPS] = {0};
        int vc = 0;
        if (parse_audit_request(buf, blen, argbuf, sizeof(argbuf), av, PS_NL_MAX_ARGS, &ac,
                                via_chain, PS_NL_MAX_VIA_HOPS, &vc) != 0 || ac < 1) {
            const char *e = "{\"type\":\"error\",\"message\":\"bad request\"}";
            ps_ap_write_frame(&io, e, strlen(e));
            goto out;
        }
        /* C-2 / M-3: allowlist the kind (against the allowlist matching the
         * request verb) and validate each arg before handing them to execvp.
         * JSON-content tricks (escape sequences, embedded NULs, key-order
         * confusion) all bottom out here. */
        if (!kind_is_allowed(av[0], is_probe)) {
            const char *e = "{\"type\":\"error\",\"message\":\"unknown kind\"}";
            ps_ap_write_frame(&io, e, strlen(e));
            goto out;
        }
        for (int i = 1; i < ac; i++) {
            if (!arg_is_safe(av[i])) {
                const char *e = "{\"type\":\"error\",\"message\":\"unsafe audit argument\"}";
                ps_ap_write_frame(&io, e, strlen(e));
                goto out;
            }
        }
        /* via_chain hops must also be safe -- they become --via args
         * to the subprocess. */
        for (int i = 0; i < vc; i++) {
            if (!arg_is_safe(via_chain[i])) {
                const char *e = "{\"type\":\"error\",\"message\":\"unsafe via_chain entry\"}";
                ps_ap_write_frame(&io, e, strlen(e));
                goto out;
            }
        }
        run_subprocess(st, is_probe, av[0], av, ac, via_chain, vc, &io);
        dispatched = 1;
    }

out:
    ps_at_close(ssl);
    atomic_fetch_sub(&st->active_clients, 1);
    return NULL;
}

/* ---- accept loop ------------------------------------------------- */

static void *accept_thread_fn(void *arg) {
    struct nl_state *st = arg;
    while (!atomic_load(&st->stop)) {
        struct sockaddr_in ca; socklen_t cal = sizeof(ca);
        int cfd = accept(st->listen_fd, (struct sockaddr *)&ca, &cal);
        if (cfd < 0) { if (errno == EINTR) continue; break; }

        if (atomic_load(&st->active_clients) >= st->max_clients) {
            close(cfd);
            ps_warn("network_listener: at client cap (%d); dropping connection",
                    st->max_clients);
            continue;
        }
        /* Route through ps_at_accept_fd so the TLS handshake AND fingerprint
         * enforcement happen in one place. We then immediately gate on the
         * authorized-keys list before any application data flows. */
        SSL *ssl = ps_at_accept_fd(&st->tctx, cfd);
        if (!ssl) continue;
        if (!is_authorized(st, ssl)) {
            ps_at_close(ssl);  /* silent drop, no hello frame leak */
            continue;
        }

        struct session_args *sa = calloc(1, sizeof(*sa));
        if (!sa) { ps_at_close(ssl); continue; }
        sa->st = st; sa->ssl = ssl;
        atomic_fetch_add(&st->active_clients, 1);
        pthread_t tid;
        if (pthread_create(&tid, NULL, session_thread, sa) != 0) {
            atomic_fetch_sub(&st->active_clients, 1);
            ps_at_close(ssl); free(sa);
            continue;
        }
        pthread_detach(tid);
    }
    return NULL;
}

/* ---- init / shutdown -------------------------------------------- */

static int nl_init(ps_module_ctx_t *ctx) {
    /* Two modes:
     *   PS_AGENT_LISTEN_MODE=persistent    open a TCP listener, accept loop
     *   PS_AGENT_LISTEN_MODE=knock         no idle listener; sessions land
     *                                       only via ps_nl_open_session_window
     *                                       called from discovery_listener
     *   PS_AGENT_LISTEN_MODE=both          both paths active
     *
     * Legacy: PS_AGENT_LISTEN_ENABLED=1 means 'persistent'. */
    const char *mode_env = getenv("PS_AGENT_LISTEN_MODE");
    const char *legacy   = getenv("PS_AGENT_LISTEN_ENABLED");
    int do_persistent = 0, do_knock = 0;
    if (mode_env && *mode_env) {
        if      (strcmp(mode_env, "persistent") == 0) do_persistent = 1;
        else if (strcmp(mode_env, "knock")      == 0) do_knock      = 1;
        else if (strcmp(mode_env, "both")       == 0) { do_persistent = 1; do_knock = 1; }
    } else if (legacy && strcmp(legacy, "1") == 0) {
        do_persistent = 1;
    }
    if (!do_persistent && !do_knock) {
        ps_info("network_listener: disabled (set PS_AGENT_LISTEN_MODE=persistent|knock|both)");
        ctx->userdata = NULL;
        return 0;
    }

    struct nl_state *st = calloc(1, sizeof(*st));
    if (!st) return -1;
    st->listen_fd = -1;
    st->max_clients = 64;
    const char *mc = getenv("PS_AGENT_MAX_CLIENTS");
    if (mc && *mc) st->max_clients = atoi(mc);
    const char *bin = getenv("PS_PACKETSONDE_BIN");
    snprintf(st->packetsonde_bin, sizeof(st->packetsonde_bin),
             "%s", (bin && *bin) ? bin : "packetsonde");

    /* Identity key. */
    char kdir[1024];
    const char *kd = getenv("PS_KEY_DIR");
    if (kd && *kd) snprintf(kdir, sizeof(kdir), "%s", kd);
    else if (ps_keystore_default_dir(kdir, sizeof(kdir)) != 0) { free(st); return -1; }
    const char *kname = getenv("PS_AGENT_LISTEN_KEY");
    if (!kname || !*kname) kname = "agent";
    if (ps_keystore_load(kdir, kname, &st->agent_kp) != 0) {
        ps_warn("network_listener: cannot load '%s' from %s", kname, kdir);
        free(st); return -1;
    }
    int has_sec = 0;
    for (size_t i = 0; i < PS_KEYSTORE_SECKEY_SIZE; i++)
        if (st->agent_kp.seckey[i]) { has_sec = 1; break; }
    if (!has_sec) {
        ps_warn("network_listener: agent key is pubkey-only");
        free(st); return -1;
    }

    char auth_dir[1100];
    const char *ad = getenv("PS_AGENT_AUTHORIZED_DIR");
    if (ad && *ad) snprintf(auth_dir, sizeof(auth_dir), "%s", ad);
    else snprintf(auth_dir, sizeof(auth_dir), "%s/authorized", kdir);
    load_authorized(st, auth_dir);

    /* Opt-in SIGPIPE block (#11): the agent has nontrivial cleanup
     * paths -- don't get killed by a half-closed client mid-write. */
    ps_at_block_sigpipe();
    if (ps_at_ctx_init(&st->tctx, PS_AT_SERVER, &st->agent_kp, NULL) != 0) {
        free(st); return -1;
    }

    atomic_init(&st->stop, 0);
    atomic_init(&st->active_clients, 0);

    if (do_persistent) {
        const char *addr = getenv("PS_AGENT_LISTEN_ADDR");
        if (!addr || !*addr) addr = "0.0.0.0";
        int port = 8442;
        const char *ps = getenv("PS_AGENT_LISTEN_PORT");
        if (ps && *ps) port = atoi(ps);

        st->listen_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (st->listen_fd < 0) { ps_at_ctx_destroy(&st->tctx); free(st); return -1; }
        int one = 1;
        setsockopt(st->listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        struct sockaddr_in la; memset(&la, 0, sizeof(la));
        la.sin_family = AF_INET;
        la.sin_port = htons((uint16_t)port);
        inet_aton(addr, &la.sin_addr);
        if (bind(st->listen_fd, (struct sockaddr *)&la, sizeof(la)) != 0) {
            ps_warn("network_listener: bind %s:%d failed: %s", addr, port, strerror(errno));
            close(st->listen_fd); ps_at_ctx_destroy(&st->tctx); free(st); return -1;
        }
        if (listen(st->listen_fd, 16) != 0) {
            close(st->listen_fd); ps_at_ctx_destroy(&st->tctx); free(st); return -1;
        }
        if (pthread_create(&st->accept_tid, NULL, accept_thread_fn, st) != 0) {
            close(st->listen_fd); ps_at_ctx_destroy(&st->tctx); free(st); return -1;
        }
        st->running = 1;
        ps_info("network_listener: persistent mode -- listening on %s:%d, max %d clients",
                addr, port, st->max_clients);
    } else {
        ps_info("network_listener: knock-only mode -- no idle listener; "
                "sessions land via discovery probes");
    }
    ctx->userdata = st;
    g_state = st;
    return 0;
}

static void nl_shutdown(ps_module_ctx_t *ctx) {
    struct nl_state *st = ctx->userdata;
    if (!st) return;
    atomic_store(&st->stop, 1);
    if (st->listen_fd >= 0) {
        /* shutdown() before close(): the accept thread is blocked in
         * accept() on this fd, and close() alone does NOT unblock a
         * concurrent accept() (the in-flight call keeps waiting on the old
         * file description) -- the pthread_join below would then hang
         * forever. shutdown(SHUT_RDWR) wakes accept() so the thread sees
         * ->stop and exits cleanly. */
        shutdown(st->listen_fd, SHUT_RDWR);
        close(st->listen_fd);
    }
    if (st->running) pthread_join(st->accept_tid, NULL);
    ps_at_ctx_destroy(&st->tctx);
    free(st);
    ctx->userdata = NULL;
    g_state = NULL;
}

/* ---- Knock-mode one-shot session window ----------------------------
 *
 * Called from discovery_listener when a signed probe carrying
 * PS_DISCOVERY_FLAG_REQUEST_SESSION arrives. We bind a fresh TCP socket
 * on 0.0.0.0:0, hand it to a dedicated accept thread that lives for
 * `timeout_secs`, and return the kernel-picked port so the discovery
 * reply can advertise it.
 *
 * Beyond the window, the port is gone -- net effect: an external port
 * scan sees nothing between knocks.
 *
 * Requires the network_listener module to be enabled (we reuse its
 * SSL_CTX, authorized-keys list, and session_thread). If the module is
 * disabled, returns -1.
 */

struct window_args {
    int                listen_fd;
    int                timeout_secs;
};

static void *window_thread(void *arg) {
    struct window_args *wa = arg;
    int lfd = wa->listen_fd;
    int timeout = wa->timeout_secs;
    free(wa);
    if (!g_state) { close(lfd); return NULL; }

    struct timeval tv = { timeout, 0 };
    setsockopt(lfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct sockaddr_in ca; socklen_t cal = sizeof(ca);
    int cfd = accept(lfd, (struct sockaddr *)&ca, &cal);
    close(lfd); /* one-shot: tear down the listener before doing TLS */
    if (cfd < 0) return NULL;

    if (atomic_load(&g_state->active_clients) >= g_state->max_clients) {
        close(cfd);
        return NULL;
    }
    SSL *ssl = ps_at_accept_fd(&g_state->tctx, cfd);
    if (!ssl) return NULL;
    if (!is_authorized(g_state, ssl)) {
        ps_at_close(ssl);  /* silent drop; no hello frame leak */
        return NULL;
    }

    struct session_args *sa = calloc(1, sizeof(*sa));
    if (!sa) { ps_at_close(ssl); return NULL; }
    sa->st = g_state; sa->ssl = ssl;
    atomic_fetch_add(&g_state->active_clients, 1);
    pthread_t tid;
    if (pthread_create(&tid, NULL, session_thread, sa) != 0) {
        atomic_fetch_sub(&g_state->active_clients, 1);
        ps_at_close(ssl); free(sa);
        return NULL;
    }
    pthread_detach(tid);
    return NULL;
}

int ps_nl_open_session_window(int timeout_secs, uint16_t *out_port) {
    if (!g_state) return -1;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in la; memset(&la, 0, sizeof(la));
    la.sin_family = AF_INET;
    la.sin_addr.s_addr = htonl(INADDR_ANY);
    la.sin_port = 0;
    if (bind(fd, (struct sockaddr *)&la, sizeof(la)) != 0) { close(fd); return -1; }
    if (listen(fd, 1) != 0) { close(fd); return -1; }
    socklen_t ll = sizeof(la);
    if (getsockname(fd, (struct sockaddr *)&la, &ll) != 0) { close(fd); return -1; }
    *out_port = ntohs(la.sin_port);

    struct window_args *wa = calloc(1, sizeof(*wa));
    if (!wa) { close(fd); return -1; }
    wa->listen_fd = fd;
    wa->timeout_secs = timeout_secs > 0 ? timeout_secs : 5;
    pthread_t tid;
    if (pthread_create(&tid, NULL, window_thread, wa) != 0) {
        close(fd); free(wa); return -1;
    }
    pthread_detach(tid);
    return 0;
}

const ps_module_t network_listener_module = {
    .name        = "network_listener",
    .description = "Accept --via sessions over mTLS",
    .version     = "1.0",
    .flags       = 0,
    .init        = nl_init,
    .shutdown    = nl_shutdown,
    .on_packet   = NULL,
    .on_job      = NULL,
    .on_response = NULL,
    .tick        = NULL,
};

/* Self-registration via constructor was deleted -- main.c registers
 * this module explicitly so the global registry exists by then. */
