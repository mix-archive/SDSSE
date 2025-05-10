#ifndef AURA_SSECLIENTHANDLER_H
#define AURA_SSECLIENTHANDLER_H

#include "BloomFilter.h"
#include "GGMTree.h"
#include "Server/SSEServerClient.h"
#include <cstdint>
#include <string>
#include <tuple>
#include <unordered_map>
#include <vector>

enum OP { INS, DEL };

class SSEClientHandler {
private:
  uint8_t *key = (unsigned char *)"0123456789123456";
  uint8_t *iv = (unsigned char *)"0123456789123456";

  GGMTree *tree;
  int GGM_SIZE;
  BloomFilter<32, HASH_SIZE> *delete_bf;
  std::unordered_map<std::string, int> C; // search time

  // batching support
  static constexpr size_t BATCH_SIZE = 8192;
  std::vector<std::tuple<std::string, std::string, std::vector<std::string>>>
      pending_entries;

  void flush_batch();

  SSEServerClient *server;

public:
  // If init_remote is true (default), constructor will reset/initialise the
  // corresponding server-side handler. Set it to false when you only want to
  // connect to an existing database without wiping its contents.
  SSEClientHandler(int ins_size, int del_size, bool init_remote = true);
  SSEClientHandler(int ins_size, int del_size, const std::string &db_id,
                   const std::string &host = "127.0.0.1", uint16_t port = 5000,
                   bool init_remote = true);
  ~SSEClientHandler();
  void update(OP op, const std::string &keyword, int ind, uint8_t *content,
              size_t content_len);
  std::vector<std::string> search(const std::string &keyword);

  // Force commit any pending batched entries to the server immediately.
  void flush() { flush_batch(); }
};

#endif // AURA_SSECLIENTHANDLER_H
