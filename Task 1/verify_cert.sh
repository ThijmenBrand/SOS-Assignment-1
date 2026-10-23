#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# verify_cert.sh - Task 1, step (4)
#
# Verifies the web server certificate against the root CA certificate, and
# checks the properties the task requires (RSA 4096, SHA-256, 10 / 2 years).
#
# "openssl verify says OK" only answers one narrow question: does a signature
# chain lead from this certificate to a trusted root. It says nothing about
# whether the certificate is fit for use as a TLS server certificate - a cert
# with no subjectAltName verifies perfectly and is still rejected by every
# browser. This script therefore checks both the chain AND fitness for purpose.
# ---------------------------------------------------------------------------

# Note: config.sh sets -e, which would abort on the first failing check. Checks
# here are deliberately allowed to fail so that all of them get reported, so -e
# is switched back off after sourcing.
source "$(dirname "${BASH_SOURCE[0]}")/config.sh"
set +e

PASS=0
FAIL=0

# ok/no record a result and keep going, instead of aborting on the first problem.
ok() { printf '    \033[32m[ PASS ]\033[0m %s\n' "$*"; PASS=$((PASS + 1)); }
no() { printf '    \033[31m[ FAIL ]\033[0m %s\n' "$*"; FAIL=$((FAIL + 1)); }

# check <description> <command...>  - passes when the command exits 0
check() {
    local desc="$1"; shift
    if "$@" >/dev/null 2>&1; then ok "$desc"; else no "$desc"; fi
}

# grep the human-readable dump of a certificate for an expected string
cert_has() {
    local file="$1" pattern="$2" desc="$3"
    if openssl x509 -in "$file" -noout -text 2>/dev/null | grep -q -- "$pattern"; then
        ok "$desc"
    else
        no "$desc"
    fi
}

# every input must be present before anything can be checked
for f in "$CA_CRT" "$CA_KEY" "$SERVER_CRT" "$SERVER_KEY" "$SERVER_CSR"; do
    [ -f "$f" ] || die "missing $(basename "$f") - run the create_*.sh scripts first"
done

# --- 4a. the root CA certificate itself -------------------------------------
step "Root CA certificate"

# A root is self-signed, so its subject and issuer must be identical.
ca_subj="$(openssl x509 -in "$CA_CRT" -noout -subject | sed 's/^subject= *//')"
ca_issu="$(openssl x509 -in "$CA_CRT" -noout -issuer  | sed 's/^issuer= *//')"
if [ "$ca_subj" = "$ca_issu" ]; then ok "self-signed (subject == issuer)"
else no "subject and issuer differ - this is not a root certificate"; fi

# -check_ss_sig additionally verifies the root's signature over itself, proving
# the certificate really was signed by the key it contains.
check "self-signature verifies" \
    openssl verify -check_ss_sig -CAfile "$CA_CRT" "$CA_CRT"

# Without CA:TRUE no verifier will accept it as an issuer at all.
cert_has "$CA_CRT" "CA:TRUE"            "basicConstraints = CA:TRUE"
cert_has "$CA_CRT" "Certificate Sign"   "keyUsage includes keyCertSign"
cert_has "$CA_CRT" "CRL Sign"           "keyUsage includes cRLSign"
cert_has "$CA_CRT" "${KEY_BITS} bit"    "public key is ${KEY_BITS} bit"
cert_has "$CA_CRT" "${HASH_ALGO}With"   "signed with ${HASH_ALGO}"

# -checkend N exits 0 when the certificate will NOT expire within N seconds.
# Asking for 3649 days proves the 10 year validity without any date arithmetic.
check "valid for at least ${CA_DAYS} days (10 years)" \
    openssl x509 -in "$CA_CRT" -noout -checkend $(( (CA_DAYS - 1) * 86400 ))

# --- 4b. the CA private key --------------------------------------------------
step "Root CA private key"

# Compare hashes of the public key derived from the key file and the public key
# embedded in the certificate. If they differ, ca.key cannot have signed with
# the identity in ca.crt. (Comparing public keys rather than RSA moduli keeps
# this working unchanged for an ECDSA key.)
k="$(openssl pkey -in "$CA_KEY" -passin "file:${CA_PASS}" -pubout 2>/dev/null | openssl "$HASH_ALGO")"
c="$(openssl x509 -in "$CA_CRT" -noout -pubkey 2>/dev/null | openssl "$HASH_ALGO")"
if [ -n "$k" ] && [ "$k" = "$c" ]; then ok "ca.key matches ca.crt"
else no "ca.key does not match ca.crt"; fi

# Proves the key really is encrypted at rest. An encrypted PKCS#8 key shows a
# PBES2 object identifier; an unprotected one shows rsaEncryption instead.
# This is the check that substantiates the claim that the CA key is protected.
if openssl asn1parse -in "$CA_KEY" 2>/dev/null | grep -q "PBES2"; then
    ok "ca.key is encrypted at rest (PBES2)"
else
    no "ca.key is NOT encrypted - anyone who can read it can issue certificates"
fi

# File permissions: no group or other access on the key or the passphrase.
# The mode is read with stat rather than by slicing `ls -l` output, because the
# column layout of ls is not guaranteed and breaks on ACLs or unusual names
# (shellcheck SC2012). GNU stat uses -c, BSD/macOS stat uses -f, so the GNU form
# is tried first and falls back to the BSD one.
file_mode() {
    stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1"
}
for f in "$CA_KEY" "$CA_PASS" "$SERVER_KEY"; do
    mode="$(file_mode "$f")"
    # The last two octal digits are the group and other bits; both must be 0.
    if [ "$(( mode % 100 ))" -eq 0 ]; then
        ok "$(basename "$f") not readable by group/other (mode ${mode})"
    else
        no "$(basename "$f") permissions too open (mode ${mode})"
    fi
done

# --- 4c. chain verification --------------------------------------------------
step "Chain verification (the actual step 4 of the task)"

# The core check: does a valid signature chain lead from server.crt to ca.crt.
if out="$(openssl verify -CAfile "$CA_CRT" "$SERVER_CRT" 2>&1)"; then
    ok "server.crt verifies against ca.crt"
else
    no "server.crt does NOT verify against ca.crt: $out"
fi

# -purpose sslserver additionally checks that keyUsage and extendedKeyUsage
# actually permit TLS server authentication, rather than just that the chain
# is intact.
check "server.crt is usable for purpose 'sslserver'" \
    openssl verify -CAfile "$CA_CRT" -purpose sslserver "$SERVER_CRT"

# -x509_strict enables stricter RFC 5280 conformance checks on the chain.
check "server.crt passes -x509_strict" \
    openssl verify -CAfile "$CA_CRT" -x509_strict "$SERVER_CRT"

# NEGATIVE TEST - this one must FAIL to be meaningful. Verifying without the
# real root in the trust store has to be rejected; if it succeeded, the earlier
# PASS would prove nothing about the CA at all.
if openssl verify -CAfile "$SERVER_CRT" "$SERVER_CRT" >/dev/null 2>&1; then
    no "negative test: server.crt verified WITHOUT the root CA (chain not enforced)"
else
    ok "negative test: server.crt correctly rejected without the root CA"
fi

# --- 4d. the server certificate's own properties -----------------------------
step "Server certificate"

# Unlike the root, a leaf certificate must have been signed by someone else.
s_subj="$(openssl x509 -in "$SERVER_CRT" -noout -subject | sed 's/^subject= *//')"
s_issu="$(openssl x509 -in "$SERVER_CRT" -noout -issuer  | sed 's/^issuer= *//')"
if [ "$s_subj" != "$s_issu" ]; then ok "not self-signed (subject != issuer)"
else no "server.crt is self-signed - it was not issued by the CA"; fi

if [ "$s_issu" = "$ca_subj" ]; then ok "issuer matches the root CA subject"
else no "issuer does not match the root CA subject"; fi

cert_has "$SERVER_CRT" "CA:FALSE"          "basicConstraints = CA:FALSE"
cert_has "$SERVER_CRT" "TLS Web Server"    "extendedKeyUsage = serverAuth"
cert_has "$SERVER_CRT" "Authority Key Id"  "authorityKeyIdentifier present"
cert_has "$SERVER_CRT" "Subject Key Id"    "subjectKeyIdentifier present"
cert_has "$SERVER_CRT" "${KEY_BITS} bit"   "public key is ${KEY_BITS} bit"
cert_has "$SERVER_CRT" "${HASH_ALGO}With"  "signed with ${HASH_ALGO}"

# Not expired right now, and still valid close to the full two years.
check "not expired" \
    openssl x509 -in "$SERVER_CRT" -noout -checkend 0
check "valid for at least ${SERVER_DAYS} days (2 years)" \
    openssl x509 -in "$SERVER_CRT" -noout -checkend $(( (SERVER_DAYS - 1) * 86400 ))

# server.key must belong to server.crt, otherwise the TLS handshake fails even
# though the certificate verifies fine.
k="$(openssl pkey -in "$SERVER_KEY" -pubout 2>/dev/null | openssl "$HASH_ALGO")"
c="$(openssl x509 -in "$SERVER_CRT" -noout -pubkey 2>/dev/null | openssl "$HASH_ALGO")"
if [ -n "$k" ] && [ "$k" = "$c" ]; then ok "server.key matches server.crt"
else no "server.key does not match server.crt"; fi

# --- 4e. hostname / subjectAltName -------------------------------------------
step "Hostname verification"

# LibreSSL's `openssl verify` has no -verify_hostname flag, so the SAN is read
# out of the certificate and matched here instead. Doing it explicitly also
# makes the contents visible in the output, which is useful as evidence.
san="$(openssl x509 -in "$SERVER_CRT" -noout -text \
       | grep -A1 "Subject Alternative Name" | tail -n1 | sed 's/^ *//')"

if [ -z "$san" ]; then
    # This is the single most common defect in LLM-generated PKI scripts,
    # because the models were trained on a decade of pre-2017 tutorials where
    # the CN was still honoured. Such a certificate verifies but no browser
    # accepts it.
    no "no subjectAltName - every modern client rejects this certificate"
else
    info "SAN: ${san}"
    case "$san" in
        *"DNS:${SERVER_CN}"*) ok "SAN contains ${SERVER_CN}" ;;
        *)                    no "SAN does not contain ${SERVER_CN}" ;;
    esac
    case "$san" in
        *"DNS:localhost"*)    ok "SAN contains localhost" ;;
        *)                    no "SAN does not contain localhost" ;;
    esac
fi

# The CN is checked only for completeness; modern clients ignore it entirely.
case "$s_subj" in
    *"CN=${SERVER_CN}"*) ok "CN is ${SERVER_CN} (ignored by modern clients)" ;;
    *)                   no "unexpected CN in ${s_subj}" ;;
esac

# --- summary ------------------------------------------------------------------
step "Summary"
printf '    %d passed, %d failed\n\n' "$PASS" "$FAIL"

# A non-zero exit status lets this script be used in CI or as a test harness.
[ "$FAIL" -eq 0 ] || exit 1
