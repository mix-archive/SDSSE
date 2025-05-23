#ifndef AURA_BLOOMFILTER_H
#define AURA_BLOOMFILTER_H

#include "Hash/SpookyV2.h"
#include <array>
#include <vector>

int get_BF_size(int hashes, int items, float fp);

template <size_t key_len, size_t num_of_hashes> class BloomFilter {
private:
  long num_of_bits{};
  std::vector<bool> bits;

public:
  explicit BloomFilter(long size) : num_of_bits(size), bits(size, false) {}

  void add_tag(uint8_t *key) {
    for (size_t i = 0; i < num_of_hashes; ++i) {
      long index = SpookyHash::Hash64(key, key_len, i) % num_of_bits;
      bits[index] = true;
    }
  }

  bool might_contain(uint8_t *key) {
    bool flag = true;
    for (size_t i = 0; i < num_of_hashes; ++i) {
      long index = SpookyHash::Hash64(key, key_len, i) % num_of_bits;
      flag &= bits[index];
    }
    return flag;
  }

  void reset() { bits.clear(); }

  std::array<long, num_of_hashes> static get_index(uint8_t *key,
                                                   int num_of_bits) {
    std::array<long, num_of_hashes> indexes;
    for (size_t i = 0; i < num_of_hashes; ++i) {
      long index = SpookyHash::Hash64(key, key_len, i) % num_of_bits;
      indexes[i] = index;
    }
    return indexes;
  }

  std::vector<long> search(bool value = true) {
    std::vector<long> indexes;
    for (long i = 0; i < num_of_bits; ++i) {
      if (bits[i] == value) {
        indexes.emplace_back(i);
      }
    }
    return indexes;
  }
};

#endif // AURA_BLOOMFILTER_H
