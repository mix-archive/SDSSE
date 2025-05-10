#ifndef AURA_GGMTREE_H
#define AURA_GGMTREE_H

#include "GGMNode.h"
#include <vector>

class GGMTree {
private:
  int level;

public:
  explicit GGMTree(long num_node);
  void static derive_key_from_tree(uint8_t *current_key, long offset,
                                   int start_level, int target_level);
  std::vector<GGMNode> min_coverage(std::vector<GGMNode> node_list);
  int get_level() const;
};

#endif // AURA_GGMTREE_H
