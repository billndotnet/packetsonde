#include "verbs.h"
#include "keystore.h"
#include "agent_transport.h"
#include "agent_proto.h"
#include "collect.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <signal.h>
#include <time.h>
#include <dirent.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#define MAX_AUTHORIZED 64

static volatile sig_atomic_t g_stop = 0;
static void on_sigint(int s) { (void)s; g_stop = 1; }

static size_t load_authorized(const char *dir, uint8_t pks[][32]) {
    DIR *d = opendir(dir); if (!d) return 0;
    struct dirent *de; size_t n = 0;
    while ((de = readdir(d)) && n < MAX_AUTHORIZED) {
        size_t l = strlen(de->d_name);
        if (l < 5 || strcmp(de->d_name + l - 4, ".pub") != 0) continue;
        char p[1100]; snprintf(p, sizeof p, "%s/%s", dir, de->d_name);
        FILE *f = fopen(p, "rb"); if (!f) continue;
        if (fread(pks[n], 1, 32, f) == 32) n++;
        fclose(f);
    }
    closedir(d);
    return n;
}

static int peer_authorized(SSL *ssl, const uint8_t pks[][32], size_t npk) {
    char peer[PS_KEYSTORE_FPR_HEX_SIZE];
    if (ps_at_peer_fingerprint(ssl, peer, sizeof peer) != 0) return 0;
    const char *ph = strncmp(peer, "sha256:", 7) == 0 ? peer + 7 : peer;
    for (size_t i = 0; i < npk; i++) {
        char fpr[PS_KEYSTORE_FPR_HEX_SIZE];
        ps_keystore_fingerprint(pks[i], fpr);
        if (strcmp(ph, fpr) == 0) return 1;
    }
    return 0;
}

static void now_iso(char *out, size_t cap) {
    time_t t = time(NULL); struct tm tm; gmtime_r(&t, &tm);
    strftime(out, cap, "%Y-%m-%dT%H:%M:%SZ", &tm);
}

int ps_verb_collect_run(int argc, char **argv, const struct ps_args *opts) {
    (void)opts;
    const char *listen_spec = "0.0.0.0:8442", *outpath = NULL, *keydir = NULL, *authdir = NULL;
    static struct option lo[] = {
        {"listen", required_argument, 0, 'l'}, {"out", required_argument, 0, 'o'},
        {"key-dir", required_argument, 0, 'k'}, {"authorized", required_argument, 0, 'a'},
        {0,0,0,0}
    };
    optind = 1; int c;
    while ((c = getopt_long(argc, argv, "l:o:k:a:", lo, NULL)) != -1) {
        if (c=='l') listen_spec=optarg; else if (c=='o') outpath=optarg;
        else if (c=='k') keydir=optarg; else if (c=='a') authdir=optarg;
    }
    char kdir[1024];
    if (keydir) snprintf(kdir, sizeof kdir, "%s", keydir);
    else if (ps_keystore_default_dir(kdir, sizeof kdir) != 0) { fprintf(stderr,"collect: no key dir\n"); return 1; }
    char adir[1100];
    if (authdir) snprintf(adir, sizeof adir, "%s", authdir);
    else snprintf(adir, sizeof adir, "%s/authorized", kdir);

    struct ps_keypair kp;
    if (ps_keystore_load(kdir, "agent", &kp) != 0) { fprintf(stderr,"collect: no 'agent' key in %s\n",kdir); return 1; }
    static uint8_t authpks[MAX_AUTHORIZED][32];
    size_t npk = load_authorized(adir, authpks);
    fprintf(stderr, "collect: %zu authorized pubkey(s) from %s\n", npk, adir);

    char host[256]; int port = 8442;
    { const char *colon = strrchr(listen_spec, ':');
      if (colon) { size_t hl = (size_t)(colon-listen_spec); if (hl<sizeof host){memcpy(host,listen_spec,hl);host[hl]=0;} port = atoi(colon+1); }
      else snprintf(host, sizeof host, "%s", listen_spec); }

    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1; setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in sa; memset(&sa,0,sizeof sa);
    sa.sin_family = AF_INET; sa.sin_port = htons((uint16_t)port);
    sa.sin_addr.s_addr = (strcmp(host,"0.0.0.0")==0) ? INADDR_ANY : inet_addr(host);
    if (bind(lfd,(struct sockaddr*)&sa,sizeof sa) != 0 || listen(lfd, 16) != 0) {
        fprintf(stderr, "collect: cannot bind %s:%d\n", host, port); close(lfd); return 1;
    }
    ps_at_block_sigpipe();
    signal(SIGINT, on_sigint); signal(SIGTERM, on_sigint);

    struct ps_at_ctx ctx;
    if (ps_at_ctx_init(&ctx, PS_AT_SERVER, &kp, "") != 0) { fprintf(stderr,"collect: TLS ctx init failed\n"); close(lfd); return 1; }
    FILE *outf = outpath ? fopen(outpath, "a") : NULL;
    fprintf(stderr, "collect: listening on %s:%d (Ctrl-C to stop)\n", host, port);

    while (!g_stop) {
        SSL *ssl = ps_at_accept(&ctx, lfd);
        if (!ssl) continue;
        if (!peer_authorized(ssl, authpks, npk)) {
            fprintf(stderr, "collect: rejected unauthorized peer\n"); ps_at_close(ssl); continue;
        }
        struct ps_ap_io io; ps_at_make_io(ssl, &io);
        char hello[256], selffpr[PS_KEYSTORE_FPR_HEX_SIZE];
        ps_keystore_fingerprint(kp.pubkey, selffpr);
        int hn = snprintf(hello,sizeof hello,"{\"type\":\"hello\",\"v\":%d,\"agent_fingerprint\":\"sha256:%s\"}",PS_AGENT_PROTO_VERSION,selffpr);
        if (hn>0) ps_ap_write_frame(&io, hello, (size_t)hn);

        static uint8_t buf[256*1024]; size_t blen;
        if (ps_ap_read_frame(&io, buf, sizeof buf, &blen) == PS_AP_OK) {
            char type[32];
            if (ps_ap_frame_type(buf, blen, type, sizeof type) == 0 && strcmp(type,"ingest")==0) {
                buf[blen < sizeof buf ? blen : sizeof buf - 1] = 0;
                int accepted = 0, total = 0;
                const char *arr = strstr((char*)buf, "\"envelopes\":");
                arr = arr ? strchr(arr, '[') : NULL;
                int depth = 0; const char *os = NULL;
                char rts[40]; now_iso(rts, sizeof rts);
                for (const char *p = arr; p && *p; p++) {
                    if (*p=='{') { if (depth==0) os=p; depth++; }
                    else if (*p=='}') { depth--; if (depth==0 && os) {
                        size_t ol=(size_t)(p-os)+1; static char ej[200000];
                        if (ol < sizeof ej) { memcpy(ej,os,ol); ej[ol]=0;
                            static char line[200000]; struct ps_collect_result r;
                            if (ps_collect_process(ej, authpks, npk, rts, line, sizeof line, &r) > 0) {
                                printf("%s\n", line); if (outf){fputs(line,outf);fputc('\n',outf);fflush(outf);}
                                total++; if (r.verified) accepted++;
                            }
                        }
                        os=NULL; }
                    } else if (*p==']' && depth==0) break;
                }
                fflush(stdout);
                char ack[128]; int an=snprintf(ack,sizeof ack,"{\"type\":\"ack\",\"accepted\":%d,\"rejected\":%d}",accepted,total-accepted);
                if (an>0) ps_ap_write_frame(&io, ack, (size_t)an);
            }
        }
        ps_at_close(ssl);
    }
    if (outf) fclose(outf);
    ps_at_ctx_destroy(&ctx); close(lfd);
    fprintf(stderr, "collect: stopped\n");
    return 0;
}
