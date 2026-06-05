/*
 * `packetsonde recipe sign|verify|info` — local authoring tools for signed
 * recipe envelopes. No network. Reuses the keystore + the envelope build/parse
 * primitives in src/lib.
 */
#include "authoring.h"
#include "../args.h"
#include "recipe.h"
#include "keystore.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

static int slurp_file(const char *path, uint8_t **buf, size_t *len) {
    FILE *fp = fopen(path, "rb");
    if (!fp) return -1;
    if (fseek(fp, 0, SEEK_END) != 0) { fclose(fp); return -1; }
    long sz = ftell(fp);
    if (sz < 0 || sz > 4 * 1024 * 1024) { fclose(fp); return -1; }
    rewind(fp);
    uint8_t *b = malloc((size_t)sz + 1);
    if (!b) { fclose(fp); return -1; }
    if (fread(b, 1, (size_t)sz, fp) != (size_t)sz) { free(b); fclose(fp); return -1; }
    fclose(fp); b[sz] = '\0'; *buf = b; *len = (size_t)sz;
    return 0;
}

static int64_t now_ms(void) {
    struct timeval tv; gettimeofday(&tv, NULL);
    return (int64_t)tv.tv_sec * 1000 + (int64_t)tv.tv_usec / 1000;
}

static void fmt_signed_at(int64_t ms, char *out, size_t outsz) {
    time_t t = (time_t)(ms / 1000);
    struct tm tm; gmtime_r(&t, &tm);
    strftime(out, outsz, "%Y-%m-%dT%H:%M:%SZ", &tm);
}

int ps_recipe_sign_main(int argc, char **argv, const struct ps_args *opts) {
    (void)opts;
    const char *file = NULL, *keyname = NULL, *outpath = NULL;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--key") && i + 1 < argc) keyname = argv[++i];
        else if (!strcmp(argv[i], "-o") && i + 1 < argc) outpath = argv[++i];
        else if (argv[i][0] != '-' && !file) file = argv[i];
        else { fprintf(stderr, "Usage: packetsonde recipe sign <recipe.json> --key <name> [-o <out>]\n"); return 2; }
    }
    if (!file || !keyname) { fprintf(stderr, "recipe sign: need <recipe.json> and --key <name>\n"); return 2; }

    uint8_t *bytes = NULL; size_t blen = 0;
    if (slurp_file(file, &bytes, &blen) != 0) { fprintf(stderr, "recipe sign: cannot read '%s'\n", file); return 1; }

    /* Don't sign garbage: the recipe must parse. */
    char perr[256] = "";
    struct ps_recipe *r = ps_recipe_parse_json(bytes, blen, perr, sizeof(perr));
    if (!r) { fprintf(stderr, "recipe sign: invalid recipe: %s\n", perr); free(bytes); return 1; }
    ps_recipe_free(r);

    char dir[1024];
    if (ps_keystore_default_dir(dir, sizeof(dir)) != 0) { free(bytes); return 1; }
    struct ps_keypair kp;
    if (ps_keystore_load(dir, keyname, &kp) != 0) {
        fprintf(stderr, "recipe sign: cannot load key '%s' from %s\n", keyname, dir); free(bytes); return 1;
    }

    size_t cap = blen * 2 + 1024;
    char *env = malloc(cap);
    if (!env) { free(bytes); return 1; }
    int n = ps_recipe_envelope_build(bytes, blen, &kp, now_ms(), env, cap);
    free(bytes);
    if (n < 0) { fprintf(stderr, "recipe sign: envelope build failed (key has no secret?)\n"); free(env); return 1; }

    FILE *out = outpath ? fopen(outpath, "wb") : stdout;
    if (!out) { fprintf(stderr, "recipe sign: cannot write '%s'\n", outpath); free(env); return 1; }
    fwrite(env, 1, (size_t)n, out);
    fputc('\n', out);
    if (outpath) fclose(out);
    free(env);
    return 0;
}

int ps_recipe_verify_main(int argc, char **argv, const struct ps_args *opts) {
    (void)opts;
    if (argc < 2 || argv[1][0] == '-') { fprintf(stderr, "Usage: packetsonde recipe verify <signed.json>\n"); return 2; }
    uint8_t *bytes = NULL; size_t blen = 0;
    if (slurp_file(argv[1], &bytes, &blen) != 0) { fprintf(stderr, "recipe verify: cannot read '%s'\n", argv[1]); return 1; }

    struct ps_recipe_envelope e; char err[256] = "";
    if (ps_recipe_envelope_parse(bytes, blen, &e, err, sizeof(err)) != 0) {
        fprintf(stderr, "recipe verify: bad envelope: %s\n", err); free(bytes); return 1;
    }
    free(bytes);

    int sig_ok = ps_recipe_envelope_verify_sig(&e);
    char ierr[256] = "";
    struct ps_recipe *r = ps_recipe_parse_json(e.inner_json, e.inner_json_len, ierr, sizeof(ierr));

    char fpr[PS_KEYSTORE_FPR_HEX_SIZE];
    ps_keystore_fingerprint(e.author_pub, fpr);
    char when[32]; fmt_signed_at(e.signed_at_ms, when, sizeof(when));

    printf("signature: %s\n", sig_ok ? "VALID" : "INVALID");
    printf("author:    sha256:%s\n", fpr);
    printf("signed_at: %s\n", when);
    if (r) printf("recipe:    %s v%d (schema %d, %zu steps)\n", r->name, r->version, r->schema, r->steps_n);
    else   printf("recipe:    INVALID (%s)\n", ierr);

    int ok = sig_ok && r;
    if (r) ps_recipe_free(r);
    ps_recipe_envelope_free(&e);
    return ok ? 0 : 1;
}

int ps_recipe_info_main(int argc, char **argv, const struct ps_args *opts) {
    (void)opts;
    if (argc < 2 || argv[1][0] == '-') { fprintf(stderr, "Usage: packetsonde recipe info <signed.json>\n"); return 2; }
    uint8_t *bytes = NULL; size_t blen = 0;
    if (slurp_file(argv[1], &bytes, &blen) != 0) { fprintf(stderr, "recipe info: cannot read '%s'\n", argv[1]); return 1; }

    struct ps_recipe_envelope e; char err[256] = "";
    if (ps_recipe_envelope_parse(bytes, blen, &e, err, sizeof(err)) != 0) {
        fprintf(stderr, "recipe info: bad envelope: %s\n", err); free(bytes); return 1;
    }
    free(bytes);

    char ierr[256] = "";
    struct ps_recipe *r = ps_recipe_parse_json(e.inner_json, e.inner_json_len, ierr, sizeof(ierr));
    if (!r) { fprintf(stderr, "recipe info: inner recipe invalid: %s\n", ierr); ps_recipe_envelope_free(&e); return 1; }

    char fpr[PS_KEYSTORE_FPR_HEX_SIZE]; ps_keystore_fingerprint(e.author_pub, fpr);
    char when[32]; fmt_signed_at(e.signed_at_ms, when, sizeof(when));

    printf("name:        %s\n", r->name);
    printf("version:     %d\n", r->version);
    if (r->description) printf("description: %s\n", r->description);
    printf("kind_prefix: %s\n", r->kind_prefix);
    printf("schema:      %d\n", r->schema);
    printf("steps:       %zu\n", r->steps_n);
    printf("budgets:     steps=%d recv=%d targets=%d wall_ms=%d tls_probes=%d\n",
           r->budgets.max_steps, r->budgets.max_recv_bytes, r->budgets.max_targets,
           r->budgets.max_wallclock_ms, r->budgets.max_tls_probes);
    printf("author:      sha256:%s\n", fpr);
    printf("signed_at:   %s\n", when);

    ps_recipe_free(r);
    ps_recipe_envelope_free(&e);
    return 0;
}
