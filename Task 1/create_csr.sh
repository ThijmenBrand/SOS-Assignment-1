#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# create_csr.sh - Task 1, step (2)
#
# Generates the web server's private key and its certificate signing request.
#
#   output: 2-csr/server.key  (RSA 4096, NOT encrypted - see note below)
#           2-csr/server.cnf  (config describing subject + requested exts)
#           2-csr/server.csr  (PKCS#10 certificate signing request)
#
# A PKCS#10 CSR carries three things: the public key, the requested subject
# name, and optionally requested extensions - all signed with the server's own
# private key. That self-signature is not a trust statement; its only job is
# proof of possession, i.e. proving the requester really holds the private key
# belonging to the public key inside. This stops an attacker from having the CA
# certify somebody else's public key under the attacker's name.
#
# A CSR has NO validity period. There is no such field in PKCS#10. The two year
# validity required by the task is set by the CA in create_cert.sh (-days 730).
# ---------------------------------------------------------------------------

source "$(dirname "${BASH_SOURCE[0]}")/config.sh"

step "Step 2 - Web server key and CSR (${KEY_ALGO} ${KEY_BITS})"

mkdir -p "$DIR_CSR"

guard_overwrite "$SERVER_KEY"
guard_overwrite "$SERVER_CSR"

# --- 2a. private key --------------------------------------------------------
step "Generating the web server private key"
# Note what is deliberately MISSING compared to create_ca.sh: there is no
# -aes-256-cbc, so this key has no passphrase.
#
# That is intentional and is normal practice. A web server has to come back up
# unattended after a reboot; a passphrase-protected key would make nginx/Apache
# block waiting for input. The protection therefore has to come from filesystem
# permissions (chmod 400 below) instead of encryption.
#
# The asymmetry is the point: the CA key is used rarely, by a human, and can be
# encrypted and kept offline. The server key is used on every TLS handshake, by
# a daemon, and cannot be. Different threat models, different protection.
openssl genpkey \
    -algorithm "$KEY_ALGO" \
    -pkeyopt "rsa_keygen_bits:${KEY_BITS}" \
    -out "$SERVER_KEY"

chmod 400 "$SERVER_KEY"
info "wrote $(basename "$SERVER_KEY")"

# --- 2b. CSR configuration --------------------------------------------------
step "Writing the CSR OpenSSL configuration"
cat > "$SERVER_CNF" <<CNF
[req]
default_bits       = ${KEY_BITS}
prompt             = no                 # non-interactive, required for scripting
default_md         = ${HASH_ALGO}
distinguished_name = dn
req_extensions     = v3_req             # section used because this is a CSR

[dn]
C  = ${COUNTRY}
CN = ${SERVER_CN}                       # max 64 characters

[v3_req]
# This is a leaf certificate: it must never be able to sign other certificates.
basicConstraints = critical,CA:FALSE
# digitalSignature  -> signing the key exchange in (EC)DHE handshakes
# keyEncipherment   -> legacy RSA key transport
keyUsage         = critical,digitalSignature,keyEncipherment
# This key authenticates a server - not a client, not code.
extendedKeyUsage = serverAuth
subjectAltName   = @alt_names

[alt_names]
# subjectAltName is the extension that actually matters. Since 2017 every
# mainstream client (Chrome, Firefox, curl, Go, modern OpenSSL) ignores the CN
# entirely for hostname verification - RFC 2818's CN fallback was deprecated by
# RFC 6125 and removed from implementations. A certificate with a perfect CN but
# no SAN is simply invalid for every hostname.
DNS.1 = ${SERVER_CN}
DNS.2 = localhost
IP.1  = 127.0.0.1
CNF
info "wrote $(basename "$SERVER_CNF")"

# --- 2c. the certificate signing request ------------------------------------
step "Creating the certificate signing request"
# -new builds a fresh request; the subject and the requested extensions both
# come from the config file. The request is signed with server.key, which is the
# proof-of-possession signature described above.
openssl req -new \
    -key "$SERVER_KEY" \
    -config "$SERVER_CNF" \
    -out "$SERVER_CSR"

chmod 644 "$SERVER_CSR"
info "wrote $(basename "$SERVER_CSR")"

# --- 2d. check the request before handing it to the CA -----------------------
step "Verifying the CSR"

# -verify checks the proof-of-possession signature on the request itself.
if openssl req -in "$SERVER_CSR" -noout -verify >/dev/null 2>&1; then
    info "proof-of-possession signature: OK"
else
    die "the CSR's self-signature does not verify"
fi

# Confirm the public key inside the CSR really belongs to server.key, by
# comparing hashes of both public keys. If these differ, the CSR was built from
# a different key and the issued certificate would not match the server's key.
csr_pub="$(openssl req  -in "$SERVER_CSR" -noout -pubkey | openssl "$HASH_ALGO")"
key_pub="$(openssl pkey -in "$SERVER_KEY" -pubout        | openssl "$HASH_ALGO")"
if [ "$csr_pub" = "$key_pub" ]; then
    info "public key matches server.key: OK"
else
    die "the CSR does not belong to server.key"
fi

# The requested extensions must actually appear in the request. If this section
# is missing, req_extensions was not picked up and the SAN would be absent.
if openssl req -in "$SERVER_CSR" -noout -text | grep -q "Requested Extensions"; then
    info "requested extensions present: OK"
else
    die "the CSR contains no requested extensions (req_extensions not applied)"
fi

step "Result"
openssl req -in "$SERVER_CSR" -noout -subject

printf '\nCSR created. Next: ./create_cert.sh\n'
