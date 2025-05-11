#include "CommonUtil.h"
#include <openssl/evp.h>
#include <string.h>

int sm4_encrypt(const unsigned char *plaintext, int plaintext_len,
                const unsigned char *key, const unsigned char *iv,
                unsigned char *ciphertext) {
  EVP_CIPHER_CTX *ctx;

  int len = 0;

  int ciphertext_len;

  /* Create and initialise the context */
  ctx = EVP_CIPHER_CTX_new();

  /* Initialise the encryption operation. */
  EVP_EncryptInit_ex(ctx, EVP_sm4_ctr(), NULL, key, iv);

  /* Encrypt the message */
  EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
  ciphertext_len = len;

  /* Finalise the encryption */
  EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
  ciphertext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return ciphertext_len;
}

int sm4_decrypt(const unsigned char *ciphertext, int ciphertext_len,
                const unsigned char *key, const unsigned char *iv,
                unsigned char *plaintext) {
  EVP_CIPHER_CTX *ctx;

  int len = 0;

  int plaintext_len;

  /* Create and initialise the context */
  ctx = EVP_CIPHER_CTX_new();

  /* Initialise the decryption operation. */
  EVP_DecryptInit_ex(ctx, EVP_sm4_ctr(), NULL, key, iv);

  /* decrypt the message */
  EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);
  plaintext_len = len;

  /* Finalise the encryption */
  EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
  plaintext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return plaintext_len;
}

void sm3_digest(const unsigned char *plaintext, int plaintext_len,
                unsigned char *digest) {
  unsigned int digest_len;
  EVP_MD_CTX *mdctx;

  /* Create and initialise the context */
  mdctx = EVP_MD_CTX_new();
  EVP_DigestInit_ex(mdctx, EVP_sm3(), NULL);

  /* compute the digest */
  EVP_DigestUpdate(mdctx, plaintext, plaintext_len);

  /* Finalise the digest */
  EVP_DigestFinal_ex(mdctx, digest, &digest_len);

  /* Clean up */
  EVP_MD_CTX_free(mdctx);
}

unsigned int hmac_digest(const unsigned char *plaintext, int plaintext_len,
                         const unsigned char *key, int key_len,
                         unsigned char *digest) {
  unsigned int digest_len;
  HMAC(EVP_sm3(), key, key_len, plaintext, plaintext_len, digest, &digest_len);
  return digest_len;
}

unsigned int key_derivation(const unsigned char *plaintext, int plaintext_len,
                            const unsigned char *key, int key_len,
                            unsigned char *digest) {
  unsigned char sm3_hmac_digest[DIGEST_SIZE];
  hmac_digest(plaintext, plaintext_len, key, key_len, sm3_hmac_digest);

  unsigned int digest_len;
  // shrink the digest to 16 bytes use md5
  EVP_MD_CTX *mdctx;
  mdctx = EVP_MD_CTX_new();
  EVP_DigestInit_ex(mdctx, EVP_md5(), NULL);
  EVP_DigestUpdate(mdctx, sm3_hmac_digest, DIGEST_SIZE);
  EVP_DigestFinal_ex(mdctx, digest, &digest_len);
  EVP_MD_CTX_free(mdctx);
  // clean the intermediate result to avoid side channel attack
  memset(sm3_hmac_digest, 0, DIGEST_SIZE);
  return digest_len;
}
