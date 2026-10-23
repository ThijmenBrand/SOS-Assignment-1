/*
 * task41enc.c - encrypt a message with a password.
 *
 *   1. ask the user for a message and a password
 *   2. generate a random salt and a random IV
 *   3. derive a 256 bit AES key from the password with PBKDF2-HMAC-SHA256
 *   4. encrypt the message with AES-256-GCM (gives ciphertext + auth tag)
 *   5. write base64(salt || iv || tag || ciphertext) to text.ct
 *
 * The cipher itself, the KDF and the file/base64 helpers all live in
 * common.c, so this file is only the steps above plus their cleanup.
 *
 * Build: make            Run: ./task41enc
 */
#include "common.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/rand.h>

int main(void)
{
    /* --- all state up front, so the cleanup path is simple --------------- */
    char           message[MAX_MESSAGE]   = {0};
    char           password[MAX_PASSWORD] = {0};
    char           confirm[MAX_PASSWORD]  = {0};
    unsigned char  salt[SALT_LEN]         = {0};
    unsigned char  iv[GCM_IV_LEN]         = {0};
    unsigned char  tag[GCM_TAG_LEN]       = {0};
    unsigned char  key[AES_KEY_LEN]       = {0};
    unsigned char *blob     = NULL;   /* salt || iv || tag || ciphertext     */
    char          *encoded  = NULL;   /* base64 of the above                 */
    char          *line     = NULL;   /* the base64 plus a trailing newline  */
    size_t         msg_len  = 0;
    size_t         blob_len = 0;
    size_t         enc_len  = 0;
    int            ct_len   = -1;
    int            exit_code = EXIT_FAILURE;

    /* Every error below sets err and jumps to the cleanup block, so the
     * message, the password and the key are wiped on *every* exit path and
     * not just on the happy one. */
    const char    *err = NULL;

    /* The KDF is reached through a function pointer, so switching to another
     * password hash later is a one line change. */
    kdf_fn derive_key = kdf_pbkdf2_sha256;

    /* --- 1. input -------------------------------------------------------- */
    if (prompt_line("Message to encrypt: ", message, sizeof message) != 0) {
        err = "could not read the message (it may be at most "
              XSTR(MAX_MESSAGE_CHARS) " characters)";
        goto cleanup;
    }
    if (message[0] == '\0') {
        err = "the message is empty";
        goto cleanup;
    }

    if (prompt_password("Password: ", password, sizeof password) != 0) {
        err = "could not read the password";
        goto cleanup;
    }
    if (password[0] == '\0') {
        err = "the password is empty";
        goto cleanup;
    }

    if (prompt_password("Confirm password: ", confirm, sizeof confirm) != 0) {
        err = "could not read the confirmation";
        goto cleanup;
    }
    if (strcmp(password, confirm) != 0) {
        err = "the passwords do not match";
        goto cleanup;
    }
    secure_erase(confirm, sizeof confirm);   /* done with it already */

    msg_len = strlen(message);

    /* --- 2. random salt and IV ------------------------------------------- */
    random_bytes(salt, sizeof salt);
    random_bytes(iv, sizeof iv);

    /* --- 3. password -> AES-256 key -------------------------------------- */
    if (derive_key(password, salt, sizeof salt, key, sizeof key) != 0) {
        err = "PBKDF2 key derivation failed";
        goto cleanup;
    }
    secure_erase(password, sizeof password); /* only the key is needed now */

    /* --- 4. encrypt ------------------------------------------------------ */
    blob_len = HEADER_LEN + msg_len;
    blob = malloc(blob_len);
    if (!blob) {
        err = "out of memory";
        goto cleanup;
    }

    ct_len = aes_gcm_encrypt(key, iv,
                             (const unsigned char *)message, (int)msg_len,
                             blob + OFF_CT, tag);

    secure_erase(key, sizeof key);           /* the cipher is done with it */

    if (ct_len < 0 || (size_t)ct_len != msg_len) {
        err = "AES-256-GCM encryption failed";
        goto cleanup;
    }

    /* --- 5. assemble, base64 encode, write ------------------------------- */
    memcpy(blob + OFF_SALT, salt, SALT_LEN);
    memcpy(blob + OFF_IV,   iv,   GCM_IV_LEN);
    memcpy(blob + OFF_TAG,  tag,  GCM_TAG_LEN);

    encoded = b64_encode(blob, blob_len);
    if (!encoded) {
        err = "base64 encoding failed";
        goto cleanup;
    }
    enc_len = strlen(encoded);

    /* Append a newline so text.ct is a normal text file. write_file() in the
     * common module does the open/write/close, including closing the file
     * when the write itself fails. */
    line = malloc(enc_len + 2);
    if (!line) {
        err = "out of memory";
        goto cleanup;
    }
    memcpy(line, encoded, enc_len);
    line[enc_len]     = '\n';
    line[enc_len + 1] = '\0';

    if (write_file(CT_FILENAME, line, enc_len + 1) != 0) {
        err = "could not write " CT_FILENAME;
        goto cleanup;
    }

    printf("Encrypted %zu byte message -> %s (%zu base64 characters)\n",
           msg_len, CT_FILENAME, enc_len);
    printf("  salt: %d bytes, IV: %d bytes, GCM tag: %d bytes, PBKDF2: %d iterations\n",
           SALT_LEN, GCM_IV_LEN, GCM_TAG_LEN, PBKDF2_ITERATIONS);
    exit_code = EXIT_SUCCESS;

    /* --- cleanup --------------------------------------------------------- */
cleanup:
    /* Secrets first: the plaintext, the password and the derived key. These
     * are already wiped on the paths above that are finished with them;
     * wiping twice is harmless and means no path can skip it. */
    secure_erase(message,  sizeof message);
    secure_erase(password, sizeof password);
    secure_erase(confirm,  sizeof confirm);
    secure_erase(key,      sizeof key);

    /* The blob holds the ciphertext, which is not secret, but it is cheap to
     * wipe and the buffer briefly held plaintext-derived material. */
    secure_erase(blob, blob_len);
    free(blob);
    free(encoded);
    free(line);

    secure_erase(salt, sizeof salt);
    secure_erase(iv,   sizeof iv);
    secure_erase(tag,  sizeof tag);

    if (err)
        fatal(err);      /* prints the message and exits with EXIT_FAILURE */

    return exit_code;
}
