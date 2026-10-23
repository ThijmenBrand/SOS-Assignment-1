/*
 * common.c - implementation of the shared helpers declared in common.h.
 */
#include "common.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#ifdef _WIN32
#  include <windows.h>
#else
#  include <termios.h>
#  include <unistd.h>
#endif

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/crypto.h>

/* ---- Error handling ----------------------------------------------------- */

void fatal(const char *msg)
{
    fprintf(stderr, "error: %s\n", msg);
    if (ERR_peek_error())
        ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

void secure_erase(void *p, size_t len)
{
    if (p && len)
        OPENSSL_cleanse(p, len);
}

/* ---- Key derivation ----------------------------------------------------- */

int kdf_pbkdf2_sha256(const char *password,
                      const unsigned char *salt, size_t salt_len,
                      unsigned char *key_out, size_t key_len)
{
    if (!password || !salt || !key_out)
        return -1;

    if (PKCS5_PBKDF2_HMAC(password, (int)strlen(password),
                          salt, (int)salt_len,
                          PBKDF2_ITERATIONS, EVP_sha256(),
                          (int)key_len, key_out) != 1)
        return -1;

    return 0;
}

/* ---- AES-256-GCM -------------------------------------------------------- */

/*
 * EVP_EncryptInit_ex and EVP_DecryptInit_ex have the same signature, which is
 * what makes the setup below shareable: the two directions differ only in
 * which of the pair gets called.
 */
typedef int (*evp_init_fn)(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
                           ENGINE *impl,
                           const unsigned char *key, const unsigned char *iv);

/*
 * Select the algorithm, then the IV length, then install key + IV. The order
 * matters: EVP_CTRL_GCM_SET_IVLEN has to come after the cipher is known but
 * before the IV is handed over, otherwise OpenSSL assumes the 12 byte default.
 */
static int gcm_init(EVP_CIPHER_CTX *ctx, evp_init_fn init,
                    const unsigned char *key, const unsigned char *iv)
{
    if (init(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
        return -1;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_LEN, NULL) != 1)
        return -1;
    if (init(ctx, NULL, NULL, key, iv) != 1)
        return -1;
    return 0;
}

int aes_gcm_encrypt(const unsigned char *key,
                    const unsigned char *iv,
                    const unsigned char *pt, int pt_len,
                    unsigned char *ct_out,
                    unsigned char *tag_out)
{
    if (!key || !iv || !pt || !ct_out || !tag_out || pt_len < 0)
        return -1;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return -1;

    int len = 0, ct_len = 0, ok = 0;

    if (gcm_init(ctx, EVP_EncryptInit_ex, key, iv) != 0)
        goto done;

    /* Feed in the plaintext. (No AAD is used here; if we wanted the header to
     * be authenticated as well we would pass it to EVP_EncryptUpdate with a
     * NULL output buffer first.) */
    if (EVP_EncryptUpdate(ctx, ct_out, &len, pt, pt_len) != 1)
        goto done;
    ct_len = len;

    /* Finish. For GCM this emits no extra bytes but it does finalise the tag. */
    if (EVP_EncryptFinal_ex(ctx, ct_out + ct_len, &len) != 1)
        goto done;
    ct_len += len;

    /* Fetch the authentication tag; without it the decryptor cannot verify
     * that the ciphertext is untampered. */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_LEN, tag_out) != 1)
        goto done;

    ok = 1;

done:
    EVP_CIPHER_CTX_free(ctx);   /* also wipes the key schedule */
    return ok ? ct_len : -1;
}

int aes_gcm_decrypt(const unsigned char *key,
                    const unsigned char *iv,
                    const unsigned char *ct, int ct_len,
                    const unsigned char *tag,
                    unsigned char *pt_out)
{
    if (!key || !iv || !ct || !tag || !pt_out || ct_len < 0)
        return -1;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return -1;

    int len = 0, pt_len = 0, ok = 0;

    /* Mirror image of the encryptor, same setup helper, other direction. */
    if (gcm_init(ctx, EVP_DecryptInit_ex, key, iv) != 0)
        goto done;

    if (EVP_DecryptUpdate(ctx, pt_out, &len, ct, ct_len) != 1)
        goto done;
    pt_len = len;

    /* Hand the expected tag to OpenSSL *before* finalising ... */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_LEN,
                            (void *)tag) != 1)
        goto done;

    /* ... because EVP_DecryptFinal_ex is what recomputes the tag over the
     * ciphertext and compares it. This is the integrity check: it fails on a
     * wrong password and on any tampering with salt, IV or ciphertext. */
    if (EVP_DecryptFinal_ex(ctx, pt_out + pt_len, &len) != 1)
        goto done;
    pt_len += len;

    ok = 1;

done:
    EVP_CIPHER_CTX_free(ctx);
    return ok ? pt_len : -1;
}

/* ---- Randomness --------------------------------------------------------- */

void random_bytes(unsigned char *buf, size_t len)
{
    if (RAND_bytes(buf, (int)len) != 1)
        fatal("could not obtain random bytes from the OS");
}

/* ---- Terminal input ----------------------------------------------------- */

/* Read a line, strip the newline, and complain if it did not fit. */
static int read_line(char *buf, size_t buf_size)
{
    if (fgets(buf, (int)buf_size, stdin) == NULL)
        return -1;

    size_t len = strlen(buf);
    if (len > 0 && buf[len - 1] == '\n') {
        buf[len - 1] = '\0';
        return 0;
    }

    /* No newline seen: the input was longer than the buffer. Drain the rest
     * of the line so it does not leak into the next prompt, then fail. */
    int c;
    while ((c = getchar()) != '\n' && c != EOF)
        ;
    return -1;
}

int prompt_line(const char *prompt, char *buf, size_t buf_size)
{
    fputs(prompt, stdout);
    fflush(stdout);
    return read_line(buf, buf_size);
}

int prompt_password(const char *prompt, char *buf, size_t buf_size)
{
    fputs(prompt, stdout);
    fflush(stdout);

#ifdef _WIN32
    /* Windows: clear ENABLE_ECHO_INPUT on the console input handle.
     * GetConsoleMode fails when stdin is a pipe or a file, in which case
     * there is no echo to switch off and we just read normally. */
    HANDLE in = GetStdHandle(STD_INPUT_HANDLE);
    DWORD old_mode = 0;
    int restore = 0;

    if (in != INVALID_HANDLE_VALUE && GetConsoleMode(in, &old_mode)) {
        if (SetConsoleMode(in, old_mode & ~(DWORD)ENABLE_ECHO_INPUT))
            restore = 1;
    }

    int rc = read_line(buf, buf_size);

    if (restore)
        SetConsoleMode(in, old_mode);
#else
    /* POSIX (macOS, Linux, WSL): clear the ECHO flag in the terminal
     * settings. Same story - if stdin is not a terminal, skip it. */
    struct termios old_term, new_term;
    int restore = 0;

    if (isatty(STDIN_FILENO) && tcgetattr(STDIN_FILENO, &old_term) == 0) {
        new_term = old_term;
        new_term.c_lflag &= ~(tcflag_t)ECHO;
        if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &new_term) == 0)
            restore = 1;
    }

    int rc = read_line(buf, buf_size);

    if (restore)
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &old_term);
#endif

    fputc('\n', stdout);   /* the Enter the user typed was not echoed */
    return rc;
}

/* ---- base64 ------------------------------------------------------------- */

char *b64_encode(const unsigned char *data, size_t len)
{
    if (len > (SIZE_MAX - 1) / 2)
        return NULL;

    size_t out_size = 4 * ((len + 2) / 3) + 1;
    char *out = malloc(out_size);
    if (!out)
        return NULL;

    int written = EVP_EncodeBlock((unsigned char *)out, data, (int)len);
    if (written < 0) {
        free(out);
        return NULL;
    }
    out[written] = '\0';
    return out;
}

unsigned char *b64_decode(const char *b64, size_t b64_len, size_t *out_len)
{
    if (!b64 || !out_len)
        return NULL;

    char *clean = malloc(b64_len + 1);
    if (!clean)
        return NULL;

    size_t n = 0;
    for (size_t i = 0; i < b64_len; i++) {
        char c = b64[i];
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=')
            clean[n++] = c;
    }
    clean[n] = '\0';

    if (n == 0 || n % 4 != 0) {
        free(clean);
        return NULL;
    }

    unsigned char *out = malloc(n / 4 * 3);
    if (!out) {
        free(clean);
        return NULL;
    }

    int decoded = EVP_DecodeBlock(out, (const unsigned char *)clean, (int)n);
    if (decoded < 0) {
        free(clean);
        free(out);
        return NULL;
    }

    size_t padding = 0;
    if (n >= 1 && clean[n - 1] == '=') padding++;
    if (n >= 2 && clean[n - 2] == '=') padding++;

    free(clean);

    if ((size_t)decoded < padding) {
        free(out);
        return NULL;
    }

    *out_len = (size_t)decoded - padding;
    return out;
}

/* ---- Files -------------------------------------------------------------- */

int write_file(const char *path, const void *data, size_t len)
{
    FILE *f = fopen(path, "wb");
    if (!f)
        return -1;

    int rc = (fwrite(data, 1, len, f) == len) ? 0 : -1;
    if (fclose(f) != 0)
        rc = -1;
    return rc;
}

char *read_text_file(const char *path, size_t *out_len)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return NULL;

    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long size = ftell(f);
    if (size < 0)                   { fclose(f); return NULL; }
    rewind(f);

    char *buf = malloc((size_t)size + 1);
    if (!buf) { fclose(f); return NULL; }

    size_t got = fread(buf, 1, (size_t)size, f);
    fclose(f);

    buf[got] = '\0';
    if (out_len)
        *out_len = got;
    return buf;
}
