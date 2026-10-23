#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# create_cert.sh - Task 1, step (3)
#
# The root CA signs the web server's CSR and issues server.crt.
#
#   input:  2-csr/server.csr, 1-root-ca/ca.{key,crt,pass}
#   output: 3-certificate/server_ext.cnf
#           3-certificate/server.crt (valid 2 years, SHA-256)
#
# IMPORTANT: `openssl x509 -req` discards every extension contained in the CSR.
# Not altered - absent. A CSR requesting SAN, EKU and basicConstraints produces
# a certificate with a completely empty extensions section unless the extensions
# are supplied again at signing time. LibreSSL's x509 has no -copy_extensions
# flag at all, so they must come from an -extfile.
#
# That is also the correct trust model: the requester asks, the CA decides. The
# CSR says what the server wants; server_ext.cnf says what the CA is willing to
# assert. A real CA would validate each requested SAN entry against its
# authorisation records before writing it here - this script copies them from
# config.sh, so that validation step is manual.
# ---------------------------------------------------------------------------

source "$(dirname "${BASH_SOURCE[0]}")/config.sh"

step "Step 3 - Signing the CSR with the root CA (${SERVER_DAYS} days)"

mkdir -p "$DIR_CRT"

# The CA and the request must both exist before anything can be signed.
[ -f "$CA_KEY" ]     || die "missing $(basename "$CA_KEY") - run ./create_ca.sh first"
[ -f "$CA_CRT" ]     || die "missing $(basename "$CA_CRT") - run ./create_ca.sh first"
[ -f "$SERVER_CSR" ] || die "missing $(basename "$SERVER_CSR") - run ./create_csr.sh first"

guard_overwrite "$SERVER_CRT"

# --- 3a. extensions the CA asserts ------------------------------------------
step "Writing the CA-controlled extensions file"
cat > "$SERVER_EXT" <<CNF
[v3_server]
# Same leaf-certificate constraints the CSR requested - restated here because
# the CA, not the requester, decides what ends up in the certificate.
basicConstraints       = critical,CA:FALSE
keyUsage               = critical,digitalSignature,keyEncipherment
extendedKeyUsage       = serverAuth

# These two are added by the CA and were not in the CSR:
# subjectKeyIdentifier   - fingerprint of the server's public key
# authorityKeyIdentifier - points at the CA's subjectKeyIdentifier from step 1,
#                          which is how a verifier walks the chain to its issuer.
#                          Without it chain building falls back to matching
#                          issuer names, which is ambiguous once a CA has
#                          rolled its key.
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always

subjectAltName         = @alt_names

[alt_names]
DNS.1 = ${SERVER_CN}
DNS.2 = localhost
IP.1  = 127.0.0.1
CNF
info "wrote $(basename "$SERVER_EXT")"

# --- 3b. sign ----------------------------------------------------------------
step "Issuing the certificate"

# The serial number must be unique per CA and unpredictable. -CAcreateserial
# generates a random 64-bit value on first use and writes it to ca.srl;
# -CAserial then increments that existing file. The CA/Browser Forum requires at
# least 64 bits of entropy here precisely because predictable serials made
# chosen-prefix collision attacks practical - that is how the Flame malware
# forged a Microsoft code-signing certificate. The `-set_serial 01` pattern seen
# in many tutorials is a real weakness.
if [ -f "$CA_SRL" ]; then
    serial_opt=(-CAserial "$CA_SRL")
    info "using existing serial file $(basename "$CA_SRL")"
else
    serial_opt=(-CAcreateserial -CAserial "$CA_SRL")
    info "creating serial file $(basename "$CA_SRL") with a random serial"
fi

# -req            input is a CSR, not a certificate
# -CA / -CAkey    the issuer: subject name taken from ca.crt, signature made
#                 with ca.key. This is the only moment the CA key is used - in
#                 production this command runs on an offline machine.
# -passin         the CA key is encrypted, so the passphrase is required
# -days 730       the two year validity required by the task. This is where
#                 validity is set; the CSR had no such field.
# -sha256         explicit signature hash
# -extfile/-extensions  BOTH are needed. -extfile without -extensions reads the
#                 file's default (unnamed) section, which is empty in a
#                 sectioned file like this, silently producing a certificate
#                 with no extensions at all.
openssl x509 -req \
    -in "$SERVER_CSR" \
    -CA "$CA_CRT" -CAkey "$CA_KEY" -passin "file:${CA_PASS}" \
    "${serial_opt[@]}" \
    -days "$SERVER_DAYS" \
    -"$HASH_ALGO" \
    -extfile "$SERVER_EXT" -extensions v3_server \
    -out "$SERVER_CRT"

# The certificate is public material, served to every client in the handshake.
chmod 644 "$SERVER_CRT"
info "wrote $(basename "$SERVER_CRT")"

# --- 3c. sanity check --------------------------------------------------------
# Catch the silent failure mode described above immediately: a certificate whose
# extensions block is empty is unusable for TLS no matter what the chain says.
if ! openssl x509 -in "$SERVER_CRT" -noout -text | grep -q "X509v3 Subject Alternative Name"; then
    die "the issued certificate has no subjectAltName - the -extfile was not applied"
fi
info "subjectAltName present in the issued certificate: OK"

step "Result"
openssl x509 -in "$SERVER_CRT" -noout -subject -issuer -serial -dates
info "(subject != issuer: unlike the root, this certificate was signed by someone else)"

printf '\nCertificate issued. Next: ./verify_cert.sh\n'
