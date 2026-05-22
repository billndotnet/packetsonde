#ifndef PS_KEYSTORE_H
#define PS_KEYSTORE_H

/*
 * Ed25519 keypair load / save / fingerprint.
 *
 * Keys are stored as raw bytes on disk -- 32 B pubkey in <name>.pub,
 * 32 B private seed in <name>.sec (mode 0600). Fingerprints are the
 * SHA-256 of the 32-byte pubkey, rendered as 64 lowercase hex chars.
 *
 * The on-disk format is intentionally not OpenSSH or PKCS#8: this is an
 * application-layer identity, not a general-purpose key. Keep it dumb so
 * the agent doesn't need to drag a key-parsing library into the daemon.
 */

#include <stddef.h>
#include <stdint.h>

#define PS_KEYSTORE_PUBKEY_SIZE      32
#define PS_KEYSTORE_SECKEY_SIZE      32
#define PS_KEYSTORE_FPR_HEX_SIZE     65  /* 64 hex chars + NUL */

struct ps_keypair {
    uint8_t pubkey[PS_KEYSTORE_PUBKEY_SIZE];
    uint8_t seckey[PS_KEYSTORE_SECKEY_SIZE];
};

/* Generate a fresh Ed25519 keypair. Returns 0 on success. */
int ps_keystore_generate(struct ps_keypair *kp);

/* SHA-256 fingerprint of pubkey, rendered as 64 lowercase hex chars +
 * trailing NUL. out_hex must hold at least PS_KEYSTORE_FPR_HEX_SIZE bytes. */
int ps_keystore_fingerprint(const uint8_t *pubkey, char *out_hex);

/* Save to <dir>/<name>.pub and <dir>/<name>.sec (the latter chmod 0600).
 * Returns 0 on success. Parent directory must exist. */
int ps_keystore_save(const char *dir, const char *name,
                     const struct ps_keypair *kp);

/* Load from <dir>/<name>.pub and <dir>/<name>.sec. If only the public
 * key file exists, the seckey field is zeroed and the function still
 * returns 0 (useful for loading an authorized-keys entry). */
int ps_keystore_load(const char *dir, const char *name,
                     struct ps_keypair *kp);

/* Default key directory: $PS_KEY_DIR override, otherwise
 * $XDG_CONFIG_HOME/packetsonde/keys, otherwise ~/.config/packetsonde/keys.
 * Returns 0 on success. Does not create the directory. */
int ps_keystore_default_dir(char *out, size_t outsz);

/* Ed25519-sign msg with kp's secret key. sig64 receives the 64-byte signature.
 * Returns 0 on success, -1 on any OpenSSL failure. */
int ps_keystore_sign(const struct ps_keypair *kp, const uint8_t *msg,
                     size_t msg_len, uint8_t sig64[64]);

/* Verify an Ed25519 signature over msg. Returns 1 if valid, 0 otherwise. */
int ps_keystore_verify(const uint8_t *pubkey32, const uint8_t *msg,
                       size_t msg_len, const uint8_t sig64[64]);

#endif
