#ifndef AURA_GGMNODE_H
#define AURA_GGMNODE_H

extern "C" {
#include "CommonUtil.h"
}

#include <cstring>
#include <msgpack.hpp>

class GGMNode {
public:
  long index;
  int level;
  uint8_t key[SM4_BLOCK_SIZE]{};

  GGMNode() : index(0), level(0) {
    std::memset(key, 0, SM4_BLOCK_SIZE);
  }

  GGMNode(long index, int level) {
    this->index = index;
    this->level = level;
  }

  GGMNode(long index, int level, uint8_t *key) {
    this->index = index;
    this->level = level;
    std::memcpy(this->key, key, SM4_BLOCK_SIZE);
  }

  MSGPACK_DEFINE(index, level, key);
};

#endif // AURA_GGMNODE_H
