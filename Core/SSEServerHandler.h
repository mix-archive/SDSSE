#ifndef AURA_SSESERVERHANDLER_H
#define AURA_SSESERVERHANDLER_H

#include "GGMNode.h"
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

class SSEServerHandler {
private:
  std::unordered_map<std::string, std::string> tags;
  std::unordered_map<std::string, std::vector<std::string>> dict;
  std::unordered_map<long, uint8_t *> keys;
  std::unordered_map<long, long> root_key_map;
  int GGM_SIZE;

  void compute_leaf_key_maps(const std::vector<GGMNode> &node_list, int level);

public:
  explicit SSEServerHandler(int GGM_SIZE);
  void add_entries(const std::string &label, const std::string &tag,
                   std::vector<std::string> ciphertext_list);
  std::vector<std::string>
  search(uint8_t *token, const std::vector<GGMNode> &node_list, int level);
};

#endif // AURA_SSESERVERHANDLER_H
