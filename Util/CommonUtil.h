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

int sm4_encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
                unsigned char *iv, unsigned char *ciphertext);

int sm4_decrypt(unsigned char *ciphertext, int ciphertext_len,
                unsigned char *key, unsigned char *iv,
                unsigned char *plaintext);

void sm3_digest(unsigned char *plaintext, int plaintext_len,
                unsigned char *digest);

unsigned int hmac_digest(unsigned char *plaintext, int plaintext_len,
                         unsigned char *key, int key_len,
                         unsigned char *digest);

unsigned int key_derivation(unsigned char *plaintext, int plaintext_len,
                            unsigned char *key, int key_len,
                            unsigned char *digest);

#endif // AURA_COMMONUTIL_H
