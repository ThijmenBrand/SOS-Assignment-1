/*
 * common.h - shared constants, helpers and types for task41enc / task41dec.
 *
 * Everything that both the encryptor and the decryptor need lives here so the
 * two programs cannot drift apart (same salt size, same iteration count, same
 * file layout, ...).
 */
#ifndef COMMON_H
#define COMMON_H

#include <stddef.h>

#include <openssl/evp.h>

/* ---- Cryptographic parameters ------------------------------------------ */

#define AES_KEY_LEN   32    /* 256 bit key -> AES-256                        */
#define GCM_IV_LEN    12    /* 96 bit IV is the recommended size for GCM     */
#define GCM_TAG_LEN   16    /* 128 bit GCM authentication tag                */
#define SALT_LEN      16    /* 128 bit random salt for PBKDF2                */

/* PBKDF2 work factor. Higher = slower for us, but also slower for anyone
 * brute-forcing the password. 600k is the current OWASP advice for
 * PBKDF2-HMAC-SHA256. */
#define PBKDF2_ITERATIONS 600000

#define CT_FILENAME   "text.ct"   /* output of the encryptor, input of the decryptor */

/* Longest message the user may type. fgets() needs two more bytes than that:
 * one for the newline it keeps and one for the terminating NUL, which is why
 * the buffer is defined in terms of the limit and not the other way around. */
#define MAX_MESSAGE_CHARS 4094
#define MAX_MESSAGE   (MAX_MESSAGE_CHARS + 2)
#define MAX_PASSWORD  256         /* maximum password length we accept        */

/* Stringify a macro's *value* (STR alone would give the macro's name). Used to
 * put a length limit into a message without duplicating the number. */
#define STR(x)  #x
#define XSTR(x) STR(x)

/*
 * On-disk layout (before base64):
 *
 *   +--------+--------+---------+------------------+
 *   | salt   | iv     | tag     | ciphertext       |
 *   | 16 B   | 12 B   | 16 B    | len(plaintext) B |
 *   +--------+--------+---------+------------------+
 *
 * That whole blob is base64 encoded and written to text.ct. Salt and IV are
 * not secret, they only have to be unique, so storing them in the clear next
 * to the ciphertext is the normal thing to do.
 */
#define HEADER_LEN (SALT_LEN + GCM_IV_LEN + GCM_TAG_LEN)
#define OFF_SALT   0
#define OFF_IV     (OFF_SALT + SALT_LEN)
#define OFF_TAG    (OFF_IV + GCM_IV_LEN)
#define OFF_CT     HEADER_LEN

/* ---- Key derivation ----------------------------------------------------- */

/*
 * Function-pointer type for a password based key derivation function.
 * Both programs ask for "a" KDF through this type instead of calling PBKDF2
 * directly, so swapping in scrypt/Argon2 later touches one line per program.
 * Returns 0 on success, -1 on failure.
 */
typedef int (*kdf_fn)(const char *password,
                      const unsigned char *salt, size_t salt_len,
                      unsigned char *key_out, size_t key_len);

/* PBKDF2 with HMAC-SHA256; matches the kdf_fn signature. */
int kdf_pbkdf2_sha256(const char *password,
                      const unsigned char *salt, size_t salt_len,
                      unsigned char *key_out, size_t key_len);

/* ---- AES-256-GCM -------------------------------------------------------- */

/*
 * Both programs run the same cipher with the same parameters, so the cipher
 * itself lives here instead of being written out twice.
 *
 * GCM is a stream mode: the ciphertext is exactly as long as the plaintext,
 * there is no padding. So ct_out needs room for pt_len bytes, and pt_out for
 * ct_len bytes. Both functions return the number of output bytes, or -1.
 */

/* Encrypt pt into ct_out and write the 16 byte auth tag to tag_out. */
int aes_gcm_encrypt(const unsigned char *key,
                    const unsigned char *iv,
                    const unsigned char *pt, int pt_len,
                    unsigned char *ct_out,
                    unsigned char *tag_out);

/* Decrypt ct into pt_out and verify tag. Returns -1 if the tag does not
 * match (wrong password, or the file was modified); the caller must then
 * discard pt_out without looking at it. */
int aes_gcm_decrypt(const unsigned char *key,
                    const unsigned char *iv,
                    const unsigned char *ct, int ct_len,
                    const unsigned char *tag,
                    unsigned char *pt_out);

/* ---- Small helpers ------------------------------------------------------ */

/* Print msg (plus the OpenSSL error queue, if any) and exit(EXIT_FAILURE). */
void fatal(const char *msg);

/* Overwrite len bytes at p so the key/password does not linger in memory.
 * Uses OPENSSL_cleanse, which the compiler is not allowed to optimise away. */
void secure_erase(void *p, size_t len);

/* Read one line from stdin into buf (newline stripped). Returns 0 on success. */
int prompt_line(const char *prompt, char *buf, size_t buf_size);

/* Same, but turns terminal echo off while typing. Returns 0 on success. */
int prompt_password(const char *prompt, char *buf, size_t buf_size);

/* Fill buf with cryptographically secure random bytes. */
void random_bytes(unsigned char *buf, size_t len);

/* base64. Both return heap memory the caller must free(); NULL on failure.
 * b64_encode returns a NUL terminated string.
 * b64_decode writes the decoded length to *out_len. */
char          *b64_encode(const unsigned char *data, size_t len);
unsigned char *b64_decode(const char *b64, size_t b64_len, size_t *out_len);

/* Whole-file helpers. */
int   write_file(const char *path, const void *data, size_t len);
char *read_text_file(const char *path, size_t *out_len);

#endif /* COMMON_H */
