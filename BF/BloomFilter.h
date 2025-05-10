#ifndef AURA_BLOOMFILTER_H
#define AURA_BLOOMFILTER_H

#include "Hash/SpookyV2.h"
#include <vector>

int get_BF_size(int hashes, int items, float fp);

template <int key_len, int num_of_hashes> class BloomFilter {
private:
  long num_of_bits{};
  std::vector<bool> bits;

public:
  explicit BloomFilter(long num_of_bits) {
    this->num_of_bits = num_of_bits;
    bits.resize(num_of_bits, false);
  }

  void add_tag(uint8_t *key) {
    for (int i = 0; i < num_of_hashes; ++i) {
      long index = SpookyHash::Hash64(key, key_len, i) % num_of_bits;
      bits[index] = true;
    }
  }

  bool might_contain(uint8_t *key) {
    bool flag = true;
    for (int i = 0; i < num_of_hashes; ++i) {
      long index = SpookyHash::Hash64(key, key_len, i) % num_of_bits;
      flag &= bits[index];
    }
    return flag;
  }

  void reset() { bits.clear(); }

  std::vector<long> static get_index(uint8_t *key, int num_of_bits) {
    std::vector<long> indexes;
    for (int i = 0; i < num_of_hashes; ++i) {
      long index = SpookyHash::Hash64(key, key_len, i) % num_of_bits;
      indexes.emplace_back(index);
    }
    return indexes;
  }

  std::vector<long> search(bool value = true) {
    std::vector<long> indexes;
    for (int i = 0; i < num_of_bits; ++i) {
      if (bits[i] == value) {
        indexes.emplace_back(i);
      }
    }
    return indexes;
  }
};

#endif // AURA_BLOOMFILTER_H
