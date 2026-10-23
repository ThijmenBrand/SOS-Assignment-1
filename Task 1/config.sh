#!/usr/bin/env bash
# shellcheck disable=SC2034
#   SC2034 ("variable appears unused") is disabled for this entire file. Every
#   variable below IS used - but only by the four scripts that source this file,
#   and shellcheck analyses one file at a time, so it cannot see those uses.
#   Exporting the variables would silence the warning too, but that would push
#   the CA passphrase into the environment of every child process, which is
#   worse than the warning itself.
#   NOTE: a file-wide directive only works when it appears before the first
#   command in the file, which is why it sits here and not further down.
# ---------------------------------------------------------------------------
# config.sh - shared settings for all PKI scripts.
#
# This file is sourced by create_ca.sh, create_csr.sh, create_cert.sh and
# verify_cert.sh. It is not meant to be executed on its own.
#
# Everything that could differ between groups or environments lives here, so
# that the group number / hostname / key size is defined exactly once instead
# of being duplicated across four scripts.
# ---------------------------------------------------------------------------

# Fail loudly instead of silently continuing with half-made key material:
#   -e          abort on the first command that returns non-zero
#   -u          abort when an undefined variable is used (catches typos)
#   -o pipefail a failure anywhere in a pipeline fails the whole pipeline
set -euo pipefail

# --- identity ---------------------------------------------------------------

GROUP_NR="2"                                  # our group number
COUNTRY="AT"                                  # C= field required by the task
CA_CN="Group_${GROUP_NR}"                     # CN of the root CA certificate
SERVER_CN="server.group_${GROUP_NR}.local"    # CN of the web server certificate

# --- cryptographic parameters ----------------------------------------------
# Group 2 is an even number, so the task requires RSA with at least 4096 bit.
# (An odd group number would require ECDSA on secp256r1/prime256v1 instead.)
KEY_ALGO="RSA"
KEY_BITS="4096"
HASH_ALGO="sha256"                            # SHA-256 as required by the task

# --- validity ---------------------------------------------------------------
CA_DAYS="3650"                                # 10 years for the root CA
SERVER_DAYS="730"                             # 2 years for the server cert

# --- layout -----------------------------------------------------------------
# All paths are resolved relative to the directory holding the scripts, so the
# scripts work no matter which directory they are invoked from.
# Note the directory names contain spaces and a colon, which is why every
# single path expansion below is double-quoted.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

DIR_CA="${SCRIPT_DIR}/1-root-ca"
DIR_CSR="${SCRIPT_DIR}/2-csr"
DIR_CRT="${SCRIPT_DIR}/3-certificate"

CA_KEY="${DIR_CA}/ca.key"           # root CA private key (passphrase protected)
CA_CRT="${DIR_CA}/ca.crt"           # root CA self-signed certificate
CA_PASS="${DIR_CA}/ca.pass"         # file holding the CA key passphrase
CA_SRL="${DIR_CA}/ca.srl"           # serial number counter used when signing
CA_CNF="${DIR_CA}/ca.cnf"           # OpenSSL config describing the root CA

SERVER_KEY="${DIR_CSR}/server.key"  # web server private key (NOT encrypted)
SERVER_CSR="${DIR_CSR}/server.csr"  # certificate signing request
SERVER_CNF="${DIR_CSR}/server.cnf"  # OpenSSL config used to build the CSR

SERVER_CRT="${DIR_CRT}/server.crt"      # the issued web server certificate
SERVER_EXT="${DIR_CRT}/server_ext.cnf"  # extensions the CA asserts when signing

# --- CA passphrase ----------------------------------------------------------
# SECURITY NOTE (deliberate, documented weakness):
# The passphrase is hard-coded here and written to a plaintext file next to the
# key it protects. That is done purely so the whole PKI can be rebuilt by a
# grader with one command. In production the CA key would live on an offline
# machine or in an HSM and the passphrase would never touch the filesystem.
CA_PASSPHRASE="${CA_PASSPHRASE:-BierTrinken}"

# --- helpers ----------------------------------------------------------------

# Print a step header so the script output is readable as a walkthrough.
step() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }

# Print an informational sub-step.
info() { printf '    %s\n' "$*"; }

# Print an error and abort.
die() { printf '\n\033[31mERROR: %s\033[0m\n' "$*" >&2; exit 1; }

# Refuse to silently destroy existing key material. Overwriting the CA key, for
# example, would invalidate every certificate it has already signed. Set
# FORCE=1 in the environment to deliberately rebuild from scratch.
guard_overwrite() {
    local path="$1"
    if [ -e "$path" ] && [ "${FORCE:-0}" != "1" ]; then
        die "$(basename "$path") already exists. Re-run with FORCE=1 to overwrite (this invalidates anything already signed)."
    fi
}
