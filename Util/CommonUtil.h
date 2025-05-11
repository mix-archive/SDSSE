#ifndef AURA_COMMONUTIL_H
#define AURA_COMMONUTIL_H

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#define SM4_BLOCK_SIZE 16
#define DIGEST_SIZE 32
#define MAX_DB_SIZE 100000
#define HASH_SIZE 5
#define GGM_FP 0.0001
#define XSET_HASH 20
#define XSET_FP 0.0000001

int sm4_encrypt(const unsigned char *plaintext, int plaintext_len,
                const unsigned char *key, const unsigned char *iv,
                unsigned char *ciphertext);

int sm4_decrypt(const unsigned char *ciphertext, int ciphertext_len,
                const unsigned char *key, const unsigned char *iv,
                unsigned char *plaintext);

void sm3_digest(const unsigned char *plaintext, int plaintext_len,
                unsigned char *digest);

unsigned int hmac_digest(const unsigned char *plaintext, int plaintext_len,
                         const unsigned char *key, int key_len,
                         unsigned char *digest);

unsigned int key_derivation(const unsigned char *plaintext, int plaintext_len,
                            const unsigned char *key, int key_len,
                            unsigned char *digest);

#endif // AURA_COMMONUTIL_H
