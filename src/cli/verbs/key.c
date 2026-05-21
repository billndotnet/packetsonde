#include "../args.h"
#include "keystore.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>

int ps_verb_key_run(int argc, char **argv, const struct ps_args *opts);

static int ensure_dir(const char *dir) {
    /* mkdir -p style for one level, then the leaf. The leaf is the key
     * directory itself, which must be 0700 (owner-only) to prevent
     * symlink attacks on .sec files inside it -- see H-4 in the
     * security review. Parent dirs stay at 0755. */
    char p[1024]; snprintf(p, sizeof(p), "%s", dir);
    size_t n = strlen(p);
    for (size_t i = 1; i < n; i++) {
        if (p[i] == '/') {
            p[i] = '\0';
            mkdir(p, 0755);
            p[i] = '/';
        }
    }
    mkdir(p, 0700);
    struct stat st;
    if (stat(dir, &st) != 0) return -1;
    if (!S_ISDIR(st.st_mode)) return -1;
    /* If the directory already existed at a more-permissive mode, tighten
     * it. Don't ignore the failure -- a world-readable key dir is the
     * thing this whole subsystem is trying to prevent. */
    if ((st.st_mode & 0777) != 0700) {
        if (chmod(dir, 0700) != 0) return -1;
    }
    return 0;
}

static void usage(void) {
    fprintf(stderr,
        "Usage: packetsonde key <subcmd> [args...]\n"
        "\n"
        "Subcommands:\n"
        "  generate [--name NAME]      Generate a new Ed25519 keypair (default name: 'default').\n"
        "  list                        List local keys with fingerprints.\n"
        "  fingerprint <name|path>     Print SHA-256 fingerprint of a pubkey.\n"
        "  revoke <fingerprint>        Print a revocation line for agent config.\n"
        "\n"
        "Key directory: $PS_KEY_DIR / $XDG_CONFIG_HOME/packetsonde/keys.\n");
}

static int cmd_generate(int argc, char **argv) {
    const char *name = "default";
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--name") == 0 && i + 1 < argc) {
            name = argv[++i];
        } else {
            usage(); return 2;
        }
    }
    char dir[1024];
    if (ps_keystore_default_dir(dir, sizeof(dir)) != 0) return 1;
    if (ensure_dir(dir) != 0) {
        fprintf(stderr, "key generate: cannot create %s: %s\n", dir, strerror(errno));
        return 1;
    }
    /* Refuse to overwrite an existing key. */
    char p[1100];
    snprintf(p, sizeof(p), "%s/%s.sec", dir, name);
    struct stat st;
    if (stat(p, &st) == 0) {
        fprintf(stderr, "key generate: %s already exists; remove it first to rotate\n", p);
        return 1;
    }
    struct ps_keypair kp;
    if (ps_keystore_generate(&kp) != 0) {
        fprintf(stderr, "key generate: keygen failed\n"); return 1;
    }
    if (ps_keystore_save(dir, name, &kp) != 0) {
        fprintf(stderr, "key generate: save failed: %s\n", strerror(errno)); return 1;
    }
    char fpr[PS_KEYSTORE_FPR_HEX_SIZE];
    ps_keystore_fingerprint(kp.pubkey, fpr);
    printf("Generated: %s/%s.{pub,sec}\n", dir, name);
    printf("Fingerprint: sha256:%s\n", fpr);
    return 0;
}

static int cmd_list(int argc, char **argv) {
    (void)argc; (void)argv;
    char dir[1024];
    if (ps_keystore_default_dir(dir, sizeof(dir)) != 0) return 1;
    DIR *d = opendir(dir);
    if (!d) {
        fprintf(stderr, "key list: no key directory at %s\n", dir);
        return 1;
    }
    int count = 0;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        size_t n = strlen(de->d_name);
        if (n < 5 || strcmp(de->d_name + n - 4, ".pub") != 0) continue;
        char name[256];
        size_t copy = n - 4;
        if (copy >= sizeof(name)) continue;
        memcpy(name, de->d_name, copy); name[copy] = '\0';
        struct ps_keypair kp;
        if (ps_keystore_load(dir, name, &kp) != 0) continue;
        char fpr[PS_KEYSTORE_FPR_HEX_SIZE];
        ps_keystore_fingerprint(kp.pubkey, fpr);
        /* Distinguish keypair (has .sec) from pubkey-only entry. */
        char p[1024]; snprintf(p, sizeof(p), "%s/%s.sec", dir, name);
        struct stat st;
        int has_sec = (stat(p, &st) == 0);
        printf("%-20s sha256:%s  %s\n", name, fpr, has_sec ? "[private]" : "[pubkey-only]");
        count++;
    }
    closedir(d);
    if (count == 0) printf("(no keys in %s)\n", dir);
    return 0;
}

static int cmd_fingerprint(int argc, char **argv) {
    if (argc < 2) { usage(); return 2; }
    const char *arg = argv[1];
    char dir[1024];
    if (ps_keystore_default_dir(dir, sizeof(dir)) != 0) return 1;
    /* If arg looks like a path (contains '/' or ends with .pub), read it
     * directly. Otherwise treat as a name in the default key dir. */
    int is_path = (strchr(arg, '/') != NULL) ||
                  (strlen(arg) >= 4 && strcmp(arg + strlen(arg) - 4, ".pub") == 0);
    uint8_t pk[PS_KEYSTORE_PUBKEY_SIZE];
    if (is_path) {
        FILE *f = fopen(arg, "rb");
        if (!f) { fprintf(stderr, "key fingerprint: %s: %s\n", arg, strerror(errno)); return 1; }
        if (fread(pk, 1, PS_KEYSTORE_PUBKEY_SIZE, f) != PS_KEYSTORE_PUBKEY_SIZE) {
            fclose(f);
            fprintf(stderr, "key fingerprint: %s: short read (expected %d bytes)\n",
                    arg, PS_KEYSTORE_PUBKEY_SIZE);
            return 1;
        }
        fclose(f);
    } else {
        struct ps_keypair kp;
        if (ps_keystore_load(dir, arg, &kp) != 0) {
            fprintf(stderr, "key fingerprint: cannot load '%s' from %s\n", arg, dir);
            return 1;
        }
        memcpy(pk, kp.pubkey, PS_KEYSTORE_PUBKEY_SIZE);
    }
    char fpr[PS_KEYSTORE_FPR_HEX_SIZE];
    ps_keystore_fingerprint(pk, fpr);
    printf("sha256:%s\n", fpr);
    return 0;
}

static int cmd_revoke(int argc, char **argv) {
    if (argc < 2) { usage(); return 2; }
    /* This command doesn't reach out to agents -- key distribution and
     * revocation propagation are admin tooling (salt/cfengine/etc).
     * We emit the line(s) the operator should add to each agent's
     * discovery.toml. */
    printf("# Add the following to revoked_pubkeys on each agent's discovery.toml,\n");
    printf("# then push the config via your normal config management.\n");
    printf("revoked_pubkeys = [\"sha256:%s\"]\n", argv[1]);
    return 0;
}

int ps_verb_key_run(int argc, char **argv, const struct ps_args *opts) {
    (void)opts;
    if (argc < 2) { usage(); return 2; }
    const char *sub = argv[1];
    if (strcmp(sub, "generate")    == 0) return cmd_generate   (argc - 1, argv + 1);
    if (strcmp(sub, "list")        == 0) return cmd_list       (argc - 1, argv + 1);
    if (strcmp(sub, "fingerprint") == 0) return cmd_fingerprint(argc - 1, argv + 1);
    if (strcmp(sub, "revoke")      == 0) return cmd_revoke     (argc - 1, argv + 1);
    fprintf(stderr, "key: unknown subcommand '%s'\n", sub);
    usage();
    return 2;
}
