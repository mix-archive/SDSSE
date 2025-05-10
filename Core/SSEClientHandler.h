#ifndef AURA_SSECLIENTHANDLER_H
#define AURA_SSECLIENTHANDLER_H

#include "BloomFilter.h"
#include "Core/SSEServerHandler.h"
#include "GGMTree.h"

enum OP { INS, DEL };

class SSEClientHandler {
private:
  uint8_t *key = (unsigned char *)"0123456789123456";
  uint8_t *iv = (unsigned char *)"0123456789123456";

  GGMTree *tree;
  int GGM_SIZE;
  BloomFilter<32, HASH_SIZE> *delete_bf;
  std::unordered_map<std::string, int> C; // search time

  SSEServerHandler *server;

public:
  SSEClientHandler(int ins_size, int del_size);
  ~SSEClientHandler();
  void update(OP op, const std::string &keyword, int ind, uint8_t *content,
              size_t content_len);
  std::vector<std::string> search(const std::string &keyword);
};

#endif // AURA_SSECLIENTHANDLER_H
