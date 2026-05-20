#include "keystore.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

int ps_keystore_generate(struct ps_keypair *kp) {
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    if (!c) return -1;
    int rc = -1;
    EVP_PKEY *pk = NULL;
    if (EVP_PKEY_keygen_init(c) == 1 && EVP_PKEY_keygen(c, &pk) == 1) {
        size_t pl = PS_KEYSTORE_PUBKEY_SIZE;
        size_t sl = PS_KEYSTORE_SECKEY_SIZE;
        if (EVP_PKEY_get_raw_public_key(pk, kp->pubkey, &pl) == 1 &&
            EVP_PKEY_get_raw_private_key(pk, kp->seckey, &sl) == 1 &&
            pl == PS_KEYSTORE_PUBKEY_SIZE && sl == PS_KEYSTORE_SECKEY_SIZE) {
            rc = 0;
        }
    }
    if (pk) EVP_PKEY_free(pk);
    EVP_PKEY_CTX_free(c);
    return rc;
}

int ps_keystore_fingerprint(const uint8_t *pubkey, char *out_hex) {
    unsigned char dig[32];
    SHA256(pubkey, PS_KEYSTORE_PUBKEY_SIZE, dig);
    static const char *H = "0123456789abcdef";
    for (int i = 0; i < 32; i++) {
        out_hex[i * 2]     = H[dig[i] >> 4];
        out_hex[i * 2 + 1] = H[dig[i] & 0x0f];
    }
    out_hex[64] = '\0';
    return 0;
}

static int write_file(const char *path, const void *buf, size_t n, mode_t mode) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, mode);
    if (fd < 0) return -1;
    ssize_t w = write(fd, buf, n);
    close(fd);
    return (w == (ssize_t)n) ? 0 : -1;
}

static int read_file(const char *path, void *buf, size_t want) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    ssize_t r = read(fd, buf, want);
    close(fd);
    return (r == (ssize_t)want) ? 0 : -1;
}

int ps_keystore_save(const char *dir, const char *name,
                     const struct ps_keypair *kp) {
    char p[1024];
    snprintf(p, sizeof(p), "%s/%s.pub", dir, name);
    if (write_file(p, kp->pubkey, PS_KEYSTORE_PUBKEY_SIZE, 0644) != 0) return -1;
    snprintf(p, sizeof(p), "%s/%s.sec", dir, name);
    if (write_file(p, kp->seckey, PS_KEYSTORE_SECKEY_SIZE, 0600) != 0) return -1;
    return 0;
}

int ps_keystore_load(const char *dir, const char *name,
                     struct ps_keypair *kp) {
    char p[1024];
    snprintf(p, sizeof(p), "%s/%s.pub", dir, name);
    if (read_file(p, kp->pubkey, PS_KEYSTORE_PUBKEY_SIZE) != 0) return -1;
    memset(kp->seckey, 0, PS_KEYSTORE_SECKEY_SIZE);
    snprintf(p, sizeof(p), "%s/%s.sec", dir, name);
    /* secret is optional -- a pubkey-only load is valid (e.g. an
     * authorized peer's key). */
    (void)read_file(p, kp->seckey, PS_KEYSTORE_SECKEY_SIZE);
    return 0;
}

int ps_keystore_default_dir(char *out, size_t outsz) {
    const char *override = getenv("PS_KEY_DIR");
    if (override && *override) {
        return snprintf(out, outsz, "%s", override) < (int)outsz ? 0 : -1;
    }
    const char *xdg = getenv("XDG_CONFIG_HOME");
    if (xdg && *xdg) {
        return snprintf(out, outsz, "%s/packetsonde/keys", xdg) < (int)outsz ? 0 : -1;
    }
    const char *home = getenv("HOME");
    if (!home) home = "/tmp";
    return snprintf(out, outsz, "%s/.config/packetsonde/keys", home) < (int)outsz ? 0 : -1;
}
