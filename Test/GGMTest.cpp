#include "GGMTree.h"
#include <iostream>

#define TREE_SIZE 8

int main() {
  GGMTree tree(TREE_SIZE);

  // add test nodes
  std::vector<GGMNode> node_list;
  node_list.emplace_back(GGMNode(0, tree.get_level()));
  node_list.emplace_back(GGMNode(1, tree.get_level()));
  node_list.emplace_back(GGMNode(3, tree.get_level()));
  node_list.emplace_back(GGMNode(5, tree.get_level()));

  // compute min coverage
  std::vector<GGMNode> coverage = tree.min_coverage(node_list);

  // print the result
  std::cout << "The mini coverage node IDs are:" << std::endl;
  for (GGMNode node : coverage) {
    std::cout << "Node " << node.index << " in level " << node.level
              << std::endl;
  }

  return 0;
}