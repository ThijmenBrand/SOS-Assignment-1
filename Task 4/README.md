# Common .c

A requirement of the task is to extract all common functionality to external reusable modules. That is done using the common.c and common.h files. Common.h is the interface for common.c, in the .h file we define the structure of the functions and in the .c file we do the actual implementation.

## Function `kdf_pbkdf2_sha256`

### Signature
```c
int kdf_pbkdf2_sha256(
    const char *password, 
    const unsigned char *salt, 
    size_t salt_len, 
    unsigned char *key_out, 
    size_t key_len)
```

The function name spelled out is: `key deriviation function _ PBKDF2 _ SHA256`

This menas that this function performs a key deriviation based on the PBKDF2 (Password-Based Key Deriviation Function 2) and it uses the SHA256 to hash the password along with the salt to generate a unique password hash.

#### PBKDF2
This is the main part. It is a key derivation function with a sliding computational cost, which helps reduce the vulnerability to brute-force attacks.

The PBKDF2 takes a password, a unique and random salt, the number of iterations, the desired bit-length of the output key and the password length. Using these things it derives the key from the salt and the password based on the number of iterations.

[WIKI](https://en.wikipedia.org/wiki/PBKDF2)

#### SHA256
Sha256 is a cryptographic has function that converts input data into a fixed 256-bit output. It is a one-way function, so we cannot decrypt the cipher text to the plain text again.

[WIKI](https://en.wikipedia.org/wiki/SHA-2)

## Function `random_bytes`
We just ask the operation system to give us a defined set of random bits. We use the OS's PRNG (Pseudo Random Number Generator) which draws entropy from the OS's TRNG (True Random Number Generator)

More on this probably in the privacy and cryptography class :)

## Function `b64_encode`
As the function name suggests, we Base64 encode the input to this function.

There is one line in this function that need some explanation though. that is `    size_t out_size = 4 * ((len + 2) / 3) + 1;`

Base64 encoding packs every 3 input bytes, into 4 output characters. So the length of our input must be a multipicate of 3. If that is not the case, the Base64 algorithm padds the last block out to four 4 characters with `=`.

So we need to take this into account while allocating memory for the output. That is why we use this formula.

## Function `b64_decode`
This function, as the name suggests, decodes a Base64 string.

In the function you might see
```c
    size_t n = 0;
        for (size_t i = 0; i < b64_len; i++) {
            char c = b64[i];
            if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=') {
                    clean[n++] = c;
                }
        }
    clean[n] = '\0';
```

The reason for this code block is to clean the base64 string into only valid base 64 characters. The `EVP_DecodeBlock` is strict and will throw an error if there is an invalid input.

But when base64 is read from a file, the input contains new line charaers or might contain other non-base64 characters. So we need to clean the input.

Then we have this code line
```c
    if (n == 0 || n % 4 != 0) {
        free(clean);
        return NULL;
    }
```

As said in the encode function, base64 takes every three bytes and turns it into 4 characters, with optional padded `=` for the last section.

So to decode, we need to make sure that our input string is a multiplacate of 4.

After these steps, we can decode, and remove any padding that might have been added. 

# Encode.c
In the encode file, we ask the user for a password, and an input, and encode that input using the password and some more magic.

As all c programs must start. In the main

## Function `main`
We start with defining the constants and variables up top. For example for the message, the password, the salt, the IV (Initialization Vector) etc.

We define a function pointer for the `kdf_pbkdf2_sha256` function. This is done, as the inline comment says, to make switching to another hashing algorithm easy.

### Input collection
We start by collecting the users' input, which is the password and the message. We do this using the earliers defined `prompt_line` and `prompt_password` functions in the common.c file.

### Random salt and initialization vector
We choose a random salt. The salt is used to generate a unique password hash for every encrypted file, to make sure that rainbow tables won't work.

Because a rainbow table is a big table with plain text and their corresponding hashes. but if we append a random value to the plaintext, and then hash, the password might be in the rainbow table, but the hash is completely different because of this random addition.

We must however make sure to use another salt for every (password, salt) pair. Because the idea of the salt is to output completely different hashes, for the same password. So if we use the same salt twice for the same password. we know by looking at the hash that these two hashes use the same password.

We also generate a random IV (Initialization Vector) for the same logic as the salt. Because a block cipher (Block cipher: Deterministic algorithm that operates under a a fixed-length group of bits) with a fixed IV is a deterministic function. So without an IV, encrypting the same plaintext twide under the same key, provides the same ciphertext.

So we need the *random* IV to ensure that the same plaintext does does not produce the same ciphertext. It does however, not need to be secret, it is the uniqueness that matters, not the secrecy

### Key generation
The user inputted his password to encrypt the file, we generated a unique SALT and IV and now we can, based on this salt, generate the derived key from the password, using the [kdf_pbkdf2_sha256](#function-kdf_pbkdf2_sha256) we defined earlier in [common.c](#common-c)

Afterwards we remove the password from memory, as it is no longer needed. From this point, we only use the derived key.

### Encrypt
Next the fun part comes, we encrypt the actual message. We start by allocating a size for the output blob, if this fails, we remove it from memory again.

The we use the `aes_gcm_encrypt` function, along with the IV, the derived key and the plaintext to encrypt our message. We use AES (Advanced Encryption Standard) in the GCM (Galois/Counter Mode). This mode of operation of for symmetric cryptography (symmetric means encryption and decryption using the same key) provides both encryption and authentication. Authentication meaning.

After the encryption we remove the key from memory again, as it is not needed anymore.

##### aes_gcm_encrypt

#### Authentication in encryption
Authentication in encryption is any scheme that simultaniously ensures data confidentiality (the encryption itself) and data authenticity (confirming the message comes from who says it comes from).

Authenticated encryption is achieved by producing an authentiation tag alongside the ciphertext. This authentication tag verifies the message has not been tampered with and confirms the sender's identity.

Probably more on this in the cryptography class ;)

> *Some more info from AI*

> The receiver uses the same key to check the tag against the ciphertext, the nonce, and any associated data (such as an unencrypted header). If even one bit has been changed—or the wrong key or nonce is used—the check fails, and the receiver should reject the message rather than use the decrypted data. The tag confirms integrity and that the message was made by someone with the key. By itself, it doesn’t identify a particular person.

### Encode in base64 and write to file
Finally we have the encrypted ciphertext and some metadata like the salt and IV and the lengths of everything, and we can base64 encode the whole thing.

We do this using the earlier described [b64_encode](#function-b64_encode) function. after which we write it to the file, and we remove all the data from memory.

> Et voilà, we have encrypted your secret message :)

# Decode.c
Now lets decode it. Because as we have seen in ISM, encryption without a key breaches the Parkerian Hexad Utility. We have the data, but its worth nothing.

## Read file
We start by reading the input file with its base64 encoded content. We do this with the `read_text_file` function defined in common.c file. When we have the base64 encoded values we can decode them using the [b64_decode](#function-b64_decode) function.

## Split blob into needed values
We take the read text, and first check if the length of the blob is at least the same length as the header size. (The header size being the length of the Salt + IV + Tag).

```c
    if (blob_len <= HEADER_LEN) {
        err = CT_FILENAME " is truncated or empty";
        goto cleanup;
    }
```
Because if the length of the total blob is smaller then the length of the header. We can be sure that the data is corrupted.

## Prompt password
For the encryption, we derived a key based on a password. We need to prompt for that password again, to be able to derive the decryption key again. We do this again using the commonly defined `prompt_password` function in the common.c file.

## Derive key from password
From the [Split blob into needed values](#split-blob-into-needed-values) we got the IV and the SALT, and those can we now use to derive the same key we used for encryption, to decrypt.

We do this using the `derive_key` function, with underlaying the [kdf_pbkdf2_sha256](#kdf_pbkdf2_sha256) function. After we clean up the password from memory again, because it is not needed anymore.

## Decrypt and Authenticate
We start by allocating memory for the decrypted plaintext in memory. After which we can continue and use the `aes_gcm_decrypt` function. In this function we give the derived key, the gotten IV and SALT and the authentication tag.

If the cipher text or tag has been tampered with, the function will return -1. If this happens, we should not print the output and clean up.

Also after this process, we can clean up the key again, because we do not need it anymore from this point on.

## Cleanup

We clean up everything again and we are done!