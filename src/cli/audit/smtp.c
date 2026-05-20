#include "smtp.h"
#include "../output/output.h"
#include "../runstate.h"
#include "../util/fail_on.h"
#include "finding.h"
#include "ulid.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

static int parse_target(const char *spec, char *host, size_t host_sz, uint16_t *port) {
    *port = 25;
    const char *colon = strrchr(spec, ':');
    size_t hl = colon ? (size_t)(colon - spec) : strlen(spec);
    if (hl == 0 || hl >= host_sz) return -1;
    memcpy(host, spec, hl); host[hl] = '\0';
    if (colon) {
        long p = strtol(colon + 1, NULL, 10);
        if (p <= 0 || p > 65535) return -1;
        *port = (uint16_t)p;
    }
    return 0;
}

/* Read an SMTP multi-line reply. Last line has "NNN " (space after code);
 * earlier lines have "NNN-". Concatenates into out separated by \n.
 * Returns the numeric code, or 0 on error. */
static int smtp_read(int fd, char *out, size_t outsz) {
    char buf[8192]; size_t total = 0;
    int code = 0;
    size_t out_off = 0;
    if (outsz) out[0] = '\0';

    for (;;) {
        if (total >= sizeof(buf) - 1) break;
        ssize_t r = recv(fd, buf + total, sizeof(buf) - 1 - total, 0);
        if (r <= 0) break;
        total += (size_t)r;
        buf[total] = '\0';

        /* Walk complete lines */
        char *line = buf;
        for (;;) {
            char *eol = strstr(line, "\r\n");
            if (!eol) {
                /* Shift remaining partial line to front */
                size_t rem = strlen(line);
                memmove(buf, line, rem + 1);
                total = rem;
                break;
            }
            *eol = '\0';
            /* Copy line to out (drop the NNN- or NNN  prefix in output for
             * readability — keep just the text portion). */
            if (out_off + strlen(line) + 2 < outsz) {
                if (out_off) out[out_off++] = '\n';
                size_t llen = strlen(line);
                memcpy(out + out_off, line, llen);
                out_off += llen;
                out[out_off] = '\0';
            }
            if (strlen(line) >= 4) {
                if (line[3] == ' ') {
                    code = atoi(line);
                    return code;
                }
            }
            line = eol + 2;
        }
    }
    return 0;
}

static int contains_case_insensitive(const char *hay, const char *needle) {
    size_t nlen = strlen(needle);
    for (const char *p = hay; *p; p++) {
        if (strncasecmp(p, needle, nlen) == 0) return 1;
    }
    return 0;
}

int ps_audit_smtp_run(int argc, char **argv, const struct ps_args *opts) {
    if (argc < 2) {
        fprintf(stderr, "Usage: packetsonde audit smtp <host[:port]>\n");
        return 2;
    }
    char host[256]; uint16_t port = 25;
    if (parse_target(argv[1], host, sizeof(host), &port) != 0) {
        fprintf(stderr, "audit smtp: bad target '%s'\n", argv[1]);
        return 2;
    }

    char self_host[256] = ""; gethostname(self_host, sizeof(self_host));
    char run_id[PS_ULID_STRLEN + 1]; ps_ulid_new(run_id, sizeof(run_id));

    struct ps_output_opts oopts; memset(&oopts, 0, sizeof(oopts));
    switch (opts->fmt) {
        case PS_FMT_TEXT:  oopts.fmt_force = PS_OFMT_TEXT;  break;
        case PS_FMT_JSON:  oopts.fmt_force = PS_OFMT_JSON;  break;
        case PS_FMT_JSONL: oopts.fmt_force = PS_OFMT_JSONL; break;
        case PS_FMT_QUIET: oopts.fmt_force = PS_OFMT_QUIET; break;
        default:           oopts.fmt_force = 0;             break;
    }
    oopts.color = opts->no_color ? 0 : 1;
    struct ps_output out; ps_output_init(&out, &oopts);

    char portstr[8]; snprintf(portstr, sizeof(portstr), "%u", port);
    struct addrinfo hints; memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
    struct addrinfo *res = NULL;
    if (getaddrinfo(host, portstr, &hints, &res) != 0) {
        ps_output_close(&out); return 1;
    }
    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) { freeaddrinfo(res); ps_output_close(&out); return 1; }
    struct timeval tv = { 5, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    char ip[64] = "";
    struct sockaddr_in *sin = (struct sockaddr_in *)res->ai_addr;
    inet_ntop(AF_INET, &sin->sin_addr, ip, sizeof(ip));
    if (connect(fd, res->ai_addr, res->ai_addrlen) != 0) {
        freeaddrinfo(res); close(fd);
        fprintf(stderr, "audit smtp: cannot connect to %s:%u\n", host, port);
        ps_output_close(&out); return 1;
    }
    freeaddrinfo(res);

    /* Read 220 greeting */
    char greeting[1024];
    int greet_code = smtp_read(fd, greeting, sizeof(greeting));
    if (greet_code != 220) {
        close(fd);
        fprintf(stderr, "audit smtp: %s:%u did not greet (got %d)\n",
                host, port, greet_code);
        ps_output_close(&out); return 1;
    }

    /* Send EHLO */
    const char *ehlo = "EHLO packetsonde.local\r\n";
    if (send(fd, ehlo, strlen(ehlo), 0) != (ssize_t)strlen(ehlo)) {
        close(fd); ps_output_close(&out); return 1;
    }

    char ehlo_reply[4096];
    int ehlo_code = smtp_read(fd, ehlo_reply, sizeof(ehlo_reply));

    /* Polite quit */
    const char *quit = "QUIT\r\n";
    send(fd, quit, strlen(quit), 0);
    close(fd);

    /* Build the metadata finding from the greeting line. */
    char banner_e[1024]; size_t k = 0;
    for (size_t i = 0; greeting[i] && k + 2 < sizeof(banner_e); i++) {
        unsigned char c = (unsigned char)greeting[i];
        if (c == '"' || c == '\\') { banner_e[k++] = '\\'; banner_e[k++] = (char)c; }
        else if (c == '\n')        { banner_e[k++] = '\\'; banner_e[k++] = 'n'; }
        else if (c >= 0x20 && c < 0x7f) banner_e[k++] = (char)c;
    }
    banner_e[k] = '\0';

    int starttls = ehlo_code == 250 && contains_case_insensitive(ehlo_reply, "STARTTLS");
    int auth_advertised = ehlo_code == 250 && contains_case_insensitive(ehlo_reply, "AUTH ");

    {
        char ev[1400];
        snprintf(ev, sizeof(ev),
            "{\"banner\":\"%s\",\"ehlo_code\":%d,\"starttls\":%s,\"auth_advertised\":%s}",
            banner_e, ehlo_code, starttls ? "true" : "false",
            auth_advertised ? "true" : "false");
        char title[200];
        snprintf(title, sizeof(title),
                 "SMTP reachable (STARTTLS=%s, AUTH=%s)",
                 starttls ? "yes" : "no", auth_advertised ? "yes" : "no");
        struct ps_finding f;
        ps_finding_init(&f, run_id, "cli.audit.smtp", self_host,
                        "smtp.metadata", PS_SEV_INFO, PS_CONF_CONFIRMED, title);
        ps_finding_set_target_ip(&f, ip, port);
        ps_finding_set_target_hostname(&f, host, port);
        ps_finding_set_evidence_json(&f, ev);
        ps_output_emit(&out, &f);
    }

    /* No STARTTLS advertised on a port where it could be — flag.
     * Port 465 is implicit-TLS; port 25 and 587 should advertise STARTTLS. */
    if (!starttls && (port == 25 || port == 587)) {
        struct ps_finding f;
        ps_finding_init(&f, run_id, "cli.audit.smtp", self_host,
                        "smtp.no_starttls", PS_SEV_MEDIUM, PS_CONF_FIRM,
                        "SMTP server does not advertise STARTTLS (plaintext only)");
        ps_finding_set_target_ip(&f, ip, port);
        ps_finding_set_target_hostname(&f, host, port);
        ps_finding_set_evidence_json(&f, "{\"port\":25}");
        ps_output_emit(&out, &f);
    }

    ps_output_snapshot(&out, &g_last_run_counts);
    ps_output_close(&out);
    return 0;
}
