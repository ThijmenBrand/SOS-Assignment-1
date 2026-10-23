#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# create_ca.sh - Task 1, step (1)
#
# Generates the root CA's private key and its self-signed root certificate.
#
#   output: 1-root-ca/ca.key  (RSA 4096, AES-256 encrypted)
#           1-root-ca/ca.crt  (self-signed, valid 10 years, SHA-256)
#
# A root CA is the top of the trust chain. Nothing signs it, so it signs
# itself; trust in it comes from distributing ca.crt out-of-band, never from
# the signature on the certificate itself.
# ---------------------------------------------------------------------------

# Load the shared settings (paths, key size, validity, helpers).
source "$(dirname "${BASH_SOURCE[0]}")/config.sh"

step "Step 1 - Root CA (${KEY_ALGO} ${KEY_BITS}, ${CA_DAYS} days)"

# Make sure the output directory exists before writing into it.
mkdir -p "$DIR_CA"

# Do not clobber an existing CA: every certificate already signed by it would
# become unverifiable against the new one.
guard_overwrite "$CA_KEY"
guard_overwrite "$CA_CRT"

# --- 1a. passphrase file ----------------------------------------------------
# The CA private key is encrypted, so openssl needs a passphrase. Reading it
# from a file (-pass file:) instead of typing it keeps the scripts
# non-interactive, and - unlike -pass pass:secret - keeps the passphrase out of
# the shell history and out of the process list visible via `ps`.
if [ ! -f "$CA_PASS" ]; then
    info "writing passphrase file $(basename "$CA_PASS")"
    # printf without a trailing newline: a newline would become part of the
    # passphrase and every later -passin would then fail.
    printf '%s' "$CA_PASSPHRASE" > "$CA_PASS"
fi
# Read/write for the owner only. The default umask would leave it world-readable.
chmod 600 "$CA_PASS"

# --- 1b. private key --------------------------------------------------------
step "Generating the root CA private key"
# genpkey is the modern key generator (genrsa/ecparam -genkey are the legacy
# equivalents). -aes-256-cbc encrypts the key at rest: an unencrypted CA key is
# the single worst flaw possible in a PKI, because whoever can read the file can
# issue certificates that the entire chain trusts.
openssl genpkey \
    -algorithm "$KEY_ALGO" \
    -pkeyopt "rsa_keygen_bits:${KEY_BITS}" \
    -aes-256-cbc -pass "file:${CA_PASS}" \
    -out "$CA_KEY"

# The private key must never be readable by other local accounts.
chmod 400 "$CA_KEY"
info "wrote $(basename "$CA_KEY")"

# --- 1c. OpenSSL configuration for the self-signed certificate --------------
# The extensions could also be passed with `openssl req -addext ...`, but that
# flag does not exist in LibreSSL (which is what macOS ships as `openssl`), so a
# config file is used instead. It is written here rather than kept by hand so
# that the whole PKI is reproducible from the scripts alone.
step "Writing the root CA OpenSSL configuration"
cat > "$CA_CNF" <<CNF
[req]
default_bits       = ${KEY_BITS}
prompt             = no                 # never ask interactively
default_md         = ${HASH_ALGO}       # SHA-256 signature hash
distinguished_name = dn
x509_extensions    = v3_ca              # section used because of -x509

[dn]
C  = ${COUNTRY}
CN = ${CA_CN}

[v3_ca]
# CA:TRUE is what actually makes this a CA - without it every verifier rejects
# the chain. pathlen:0 means it may only sign end-entity certificates, never a
# sub-CA. 'critical' forces clients to understand the extension or reject.
basicConstraints     = critical,CA:TRUE,pathlen:0
# This key may sign certificates and revocation lists, and nothing else.
keyUsage             = critical,keyCertSign,cRLSign
# A hash of the CA public key. The server certificate references it later as
# its Authority Key Identifier so a verifier can locate the issuer.
subjectKeyIdentifier = hash
CNF
info "wrote $(basename "$CA_CNF")"

# --- 1d. self-signed root certificate ---------------------------------------
step "Creating the self-signed root certificate"
# `req -x509` does two things at once: it builds a certificate request in memory
# from the subject in the config, then immediately signs it with the same key
# instead of handing it to an external CA. That is what "self-signed" means.
#   -new      build a fresh subject rather than reading an existing CSR
#   -key      the key to both certify and sign with
#   -days     validity (3650 = 10 years, as required)
#   -sha256   explicit signature hash; some older versions still default to SHA-1
openssl req -x509 -new \
    -key "$CA_KEY" -passin "file:${CA_PASS}" \
    -config "$CA_CNF" \
    -days "$CA_DAYS" \
    -"$HASH_ALGO" \
    -out "$CA_CRT"

# The certificate is public - it has to be distributed to every client - so
# unlike the key it is deliberately world-readable.
chmod 644 "$CA_CRT"
info "wrote $(basename "$CA_CRT")"

# --- 1e. show what was produced ---------------------------------------------
step "Result"
openssl x509 -in "$CA_CRT" -noout -subject -issuer -dates
info "(subject == issuer confirms this certificate is self-signed)"

printf '\nRoot CA created. Next: ./create_csr.sh\n'
