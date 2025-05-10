#include <cstring>
#include <iostream>

extern "C" {
#include "../Util/CommonUtil.h"
}

int main() {
  auto *key = (unsigned char *)"0123456789123456";
  auto *iv = (unsigned char *)"0123456789123456";
  auto *plaintext = (unsigned char *)"The test segmentation for AES_CTR mode";

  unsigned char ciphertext[128];

  int ciphertext_len =
      aes_encrypt(plaintext, strlen((char *)plaintext), key, iv, ciphertext);

  std::cout << "Input size:" << ciphertext_len << std::endl;

  unsigned char recover[128];
  int plaintext_len = aes_decrypt(ciphertext, ciphertext_len, key, iv, recover);

  std::cout << "Output size:" << plaintext_len << std::endl;
  std::cout << "Recovered string:" << recover << std::endl;
}