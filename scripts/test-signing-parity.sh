#!/bin/bash
# Prove the agent's Ed25519 signature over a payload verifies in Python (central's
# verify path), with NO canonicalization. Builds a tiny C harness that signs a
# payload with ps_keystore_sign, then verifies it in Python with `cryptography`.
set -e
cd "$(dirname "$0")/.."
PYTHON="${PYTHON:-python3}"
cat > /tmp/sign_harness.c <<'EOF'
#include "keystore.h"
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>
static void b64(const unsigned char*in,int n,char*out){ EVP_EncodeBlock((unsigned char*)out,in,n); }
int main(void){
  struct ps_keypair kp; if (ps_keystore_generate(&kp)) return 1;
  const char *payload="{\"origin_agent_id\":\"edge-07\",\"ts\":\"t\",\"event\":{\"v\":1,\"kind\":\"tls\"}}";
  unsigned char sig[64]; if (ps_keystore_sign(&kp,(const unsigned char*)payload,strlen(payload),sig)) return 1;
  char sigb[128],pubb[128]; b64(sig,64,sigb); b64(kp.pubkey,32,pubb);
  printf("%s\n%s\n%s\n", pubb, sigb, payload);
  return 0;
}
EOF
cc /tmp/sign_harness.c -Isrc/lib build/src/lib/libpacketsonde_lib.a -lssl -lcrypto -o /tmp/sign_harness
/tmp/sign_harness > /tmp/parity.txt
"$PYTHON" - <<'PY'
import base64
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
lines = open("/tmp/parity.txt").read().splitlines()
pub = base64.b64decode(lines[0]); sig = base64.b64decode(lines[1]); payload = lines[2].encode()
Ed25519PublicKey.from_public_bytes(pub).verify(sig, payload)  # raises on failure
print("PARITY OK: C signature verified by Python over raw payload bytes")
PY
