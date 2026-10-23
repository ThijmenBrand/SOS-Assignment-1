/*
 * task41dec.c - decrypt the message produced by task41enc.
 *
 *   1. read text.ct and base64 decode it
 *   2. split the blob into salt || iv || tag || ciphertext
 *   3. ask the user for the password
 *   4. derive the same 256 bit AES key with PBKDF2-HMAC-SHA256 over the
 *      salt that came out of the file
 *   5. decrypt with AES-256-GCM and verify the authentication tag
 *   6. print the recovered message
 *
 * The cipher itself, the KDF and the file/base64 helpers all live in
 * common.c - this file and task41enc.c share them rather than each keeping
 * their own copy, which is also what keeps the two in agreement.
 *
 * Build: make            Run: ./task41dec
 */
#include "common.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/rand.h>

int main(void)
{
    char           password[MAX_PASSWORD] = {0};
    unsigned char  key[AES_KEY_LEN]       = {0};
    char          *encoded   = NULL;   /* base64 text read from text.ct     */
    unsigned char *blob      = NULL;   /* salt || iv || tag || ciphertext   */
    unsigned char *plaintext = NULL;
    size_t         encoded_len = 0, blob_len = 0, ct_len = 0;
    int            pt_len    = -1;
    int            exit_code = EXIT_FAILURE;

    /* Pointers into blob; they are only valid once the length check below
     * has passed, so they start out NULL. */
    const unsigned char *salt = NULL, *iv = NULL, *tag = NULL, *ct = NULL;

    /* As in the encryptor: one cleanup block, reached from every path, so
     * the password, the key and the plaintext are always wiped. */
    const char    *err = NULL;

    /* Same function pointer as the encryptor: both programs must agree on the
     * KDF, so both reach it the same way. */
    kdf_fn derive_key = kdf_pbkdf2_sha256;

    /* --- 1. read and base64 decode --------------------------------------- */
    encoded = read_text_file(CT_FILENAME, &encoded_len);
    if (!encoded) {
        err = "could not open " CT_FILENAME " (run ./task41enc first)";
        goto cleanup;
    }

    blob = b64_decode(encoded, encoded_len, &blob_len);
    free(encoded);
    encoded = NULL;
    if (!blob) {
        err = CT_FILENAME " does not contain valid base64";
        goto cleanup;
    }

    /* --- 2. split the blob ----------------------------------------------- */
    /* Anything shorter than the header cannot hold a salt, IV and tag, let
     * alone a message. Check before indexing into it. */
    if (blob_len <= HEADER_LEN) {
        err = CT_FILENAME " is truncated or empty";
        goto cleanup;
    }

    salt = blob + OFF_SALT;
    iv   = blob + OFF_IV;
    tag  = blob + OFF_TAG;
    ct   = blob + OFF_CT;
    ct_len = blob_len - HEADER_LEN;

    printf("Read %s: %zu byte ciphertext (+ %d byte header)\n",
           CT_FILENAME, ct_len, HEADER_LEN);

    /* --- 3. password ------------------------------------------------------ */
    if (prompt_password("Password: ", password, sizeof password) != 0) {
        err = "could not read the password";
        goto cleanup;
    }

    /* --- 4. same password + same salt -> same key ------------------------- */
    /* The salt is not secret, it only has to be identical to the one used
     * while encrypting - which is exactly why it is stored in the file. */
    if (derive_key(password, salt, SALT_LEN, key, sizeof key) != 0) {
        err = "PBKDF2 key derivation failed";
        goto cleanup;
    }
    secure_erase(password, sizeof password);  /* only the key is needed now */

    /* --- 5. decrypt and authenticate -------------------------------------- */
    plaintext = malloc(ct_len + 1);   /* +1 so we can NUL terminate for printf */
    if (!plaintext) {
        err = "out of memory";
        goto cleanup;
    }

    pt_len = aes_gcm_decrypt(key, iv, ct, (int)ct_len, tag, plaintext);

    secure_erase(key, sizeof key);            /* the cipher is done with it */

    if (pt_len < 0) {
        /* Never print or otherwise use unauthenticated plaintext. */
        err = "decryption failed: wrong password, or " CT_FILENAME
              " has been modified";
        goto cleanup;
    }

    /* --- 6. output --------------------------------------------------------- */
    plaintext[pt_len] = '\0';
    printf("Authentication tag verified.\n");
    printf("Decrypted message: %s\n", (char *)plaintext);
    exit_code = EXIT_SUCCESS;

    /* --- cleanup ----------------------------------------------------------- */
cleanup:
    /* Wiping twice on the paths above that already wiped is harmless, and it
     * means no exit path can skip it. */
    secure_erase(password, sizeof password);
    secure_erase(key,      sizeof key);

    if (plaintext) {
        secure_erase(plaintext, ct_len + 1);
        free(plaintext);
    }

    free(blob);       /* salt/IV/tag/ct point into this; none of it is secret */
    free(encoded);    /* NULL unless we failed before decoding it */

    if (err)
        fatal(err);   /* prints the message and exits with EXIT_FAILURE */

    return exit_code;
}
