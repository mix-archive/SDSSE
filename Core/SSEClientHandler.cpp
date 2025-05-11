#include "SSEClientHandler.h"
#include "BloomFilter.h"
#include "CommonUtil.h"
#include <algorithm>
#include <cstring>
#include <iterator>

using std::string, std::vector, std::set_difference, std::inserter, std::sort;

SSEClientHandler::SSEClientHandler(int ins_size, int del_size,
                                   const std::string &db_id, bool init_remote,
                                   const std::string &host, uint16_t port)
    : tree(GGM_SIZE = get_BF_size(HASH_SIZE, del_size || ins_size, GGM_FP)),
      delete_bf(GGM_SIZE), server(db_id, host, port) {
  if (init_remote) {
    server.init_handler(GGM_SIZE);
  }
}

void SSEClientHandler::update(UpdateOP op, const string &keyword, int ind,
                              uint8_t *content, size_t content_len) {
  // compute the tag
  vector<uint8_t> pair(keyword.size() + sizeof(int));
  memcpy(pair.data(), keyword.c_str(), keyword.size());
  memcpy(pair.data() + keyword.size(), (uint8_t *)&ind, sizeof(int));
  // generate the digest of tag
  vector<uint8_t> tag(DIGEST_SIZE);
  sm3_digest(pair.data(), pair.size(), tag.data());
  // process the operator
  if (op == UpdateOP::INS) {
    // get all offsets in BF
    auto indexes = BloomFilter<32, HASH_SIZE>::get_index(tag.data(), GGM_SIZE);
    sort(indexes.begin(), indexes.end());

    // get SRE ciphertext list
    vector<string> ciphertext_list(indexes.size());
    for (size_t i = 0; i < indexes.size(); ++i) {
      const auto &index = indexes[i];
      // derive a key from the offset
      uint8_t derived_key[SM4_BLOCK_SIZE];
      memcpy(derived_key, key, SM4_BLOCK_SIZE);
      GGMTree::derive_key_from_tree(derived_key, index, tree.get_level(), 0);
      // use the key to encrypt the id
      vector<uint8_t> encrypted_id(SM4_BLOCK_SIZE + content_len);
      memcpy(encrypted_id.data(), iv, SM4_BLOCK_SIZE);
      sm4_encrypt(content, content_len, derived_key, encrypted_id.data(),
                  encrypted_id.data() + SM4_BLOCK_SIZE);
      // save the encrypted id in the list
      ciphertext_list[i] =
          string((char *)encrypted_id.data(), encrypted_id.size());
    }

    // token
    uint8_t token[DIGEST_SIZE];
    hmac_digest((uint8_t *)keyword.c_str(), keyword.size(), key, SM4_BLOCK_SIZE,
                token);
    // label
    int counter = C[keyword];
    uint8_t label[DIGEST_SIZE];
    hmac_digest((uint8_t *)&counter, sizeof(int), token, DIGEST_SIZE, label);
    C[keyword]++;
    // convert tag/label to string
    string tag_str((char *)tag.data(), DIGEST_SIZE);
    string label_str((char *)label, DIGEST_SIZE);
    // enqueue entry for batch upload
    pending_entries.emplace_back(label_str, tag_str, ciphertext_list);
    if (pending_entries.size() >= BATCH_SIZE) {
      flush_batch();
    }
  } else {
    // Ensure all pending insertions are committed before deletions
    flush_batch();
    // insert the tag into BF
    delete_bf.add_tag(tag.data());
  }
}

vector<string> SSEClientHandler::search(const string &keyword) {
  // Commit any pending entries before searching
  flush_batch();
  // token
  //    cout <<
  //    duration_cast<microseconds>(system_clock::now().time_since_epoch()).count()
  //    << endl;
  uint8_t token[DIGEST_SIZE];
  hmac_digest((uint8_t *)keyword.c_str(), keyword.size(), key, SM4_BLOCK_SIZE,
              token);
  // search all deleted positions
  vector<long> bf_pos(GGM_SIZE);
  for (size_t i = 0; i < bf_pos.size(); ++i) {
    bf_pos[i] = i;
  }
  vector<long> delete_pos = delete_bf.search();
  vector<long> remain_pos;
  set_difference(bf_pos.begin(), bf_pos.end(), delete_pos.begin(),
                 delete_pos.end(), inserter(remain_pos, remain_pos.begin()));
  // generate GGM Node for the remain position
  vector<GGMNode> node_list(remain_pos.size());
  for (size_t i = 0; i < remain_pos.size(); ++i) {
    node_list[i] = GGMNode(remain_pos[i], tree.get_level());
  }
  vector<GGMNode> remain_node = tree.min_coverage(node_list);
  // compute the key set and send to the server
  for (auto &i : remain_node) {
    memcpy(i.key, key, SM4_BLOCK_SIZE);
    GGMTree::derive_key_from_tree(i.key, i.index, i.level, 0);
  }
  // give all results to the server for search
  //    cout <<
  //    duration_cast<microseconds>(system_clock::now().time_since_epoch()).count()
  //    << endl;
  std::string token_str(reinterpret_cast<char *>(token), DIGEST_SIZE);
  vector<string> res;
  if (!server.search(token_str, remain_node, tree.get_level(), res)) {
    return {};
  }
  //    cout <<
  //    duration_cast<microseconds>(system_clock::now().time_since_epoch()).count()
  //    << endl;
  return res;
}

void SSEClientHandler::flush_batch() {
  if (pending_entries.empty())
    return;
  server.add_entries_batch(pending_entries);
  pending_entries.clear();
}