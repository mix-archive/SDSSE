#include "SSEClientHandler.h"
#include <algorithm>
#include <cstring>
#include <iterator>

using std::string, std::vector, std::set_difference, std::inserter;

SSEClientHandler::SSEClientHandler(int ins_size, int del_size)
    : SSEClientHandler(ins_size, del_size, "default") {}

SSEClientHandler::SSEClientHandler(int ins_size, int del_size,
                                   const std::string &db_id,
                                   const std::string &host, uint16_t port) {
  if (del_size == 0) {
    this->GGM_SIZE = get_BF_size(HASH_SIZE, ins_size, GGM_FP);
  } else {
    this->GGM_SIZE = get_BF_size(HASH_SIZE, del_size, GGM_FP);
  }
  this->delete_bf = new BloomFilter<32, HASH_SIZE>(GGM_SIZE);
  // init the GGM Tree
  tree = new GGMTree(GGM_SIZE);

  // initialize remote server client SDK
  server = new SSEServerClient(host, port, db_id);
  // ensure server-side handler is ready with correct GGM configuration
  server->init_handler(GGM_SIZE);
}

SSEClientHandler::~SSEClientHandler() {
  flush_batch();
  delete_bf->reset();
  delete server;
  delete tree;
}

void SSEClientHandler::update(OP op, const string &keyword, int ind,
                              uint8_t *content, size_t content_len) {
  // compute the tag
  vector<uint8_t> pair(keyword.size() + sizeof(int));
  memcpy(pair.data(), keyword.c_str(), keyword.size());
  memcpy(pair.data() + keyword.size(), (uint8_t *)&ind, sizeof(int));
  // generate the digest of tag
  vector<uint8_t> tag(DIGEST_SIZE);
  sm3_digest(pair.data(), pair.size(), tag.data());
  // process the operator
  if (op == INS) {
    // get all offsets in BF
    vector<long> indexes =
        BloomFilter<32, HASH_SIZE>::get_index(tag.data(), GGM_SIZE);
    sort(indexes.begin(), indexes.end());

    // get SRE ciphertext list
    vector<string> ciphertext_list;
    for (long index : indexes) {
      // derive a key from the offset
      uint8_t derived_key[SM4_BLOCK_SIZE];
      memcpy(derived_key, key, SM4_BLOCK_SIZE);
      GGMTree::derive_key_from_tree(derived_key, index, tree->get_level(), 0);
      // use the key to encrypt the id
      vector<uint8_t> encrypted_id(SM4_BLOCK_SIZE + content_len);
      memcpy(encrypted_id.data(), iv, SM4_BLOCK_SIZE);
      sm4_encrypt(content, content_len, derived_key, encrypted_id.data(),
                  encrypted_id.data() + SM4_BLOCK_SIZE);
      // save the encrypted id in the list
      ciphertext_list.emplace_back((char *)encrypted_id.data(),
                                   encrypted_id.size());
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
    delete_bf->add_tag(tag.data());
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
  vector<long> bf_pos;
  bf_pos.reserve(GGM_SIZE);
  for (int i = 0; i < GGM_SIZE; ++i) {
    bf_pos.emplace_back(i);
  }
  vector<long> delete_pos = delete_bf->search();
  vector<long> remain_pos;
  set_difference(bf_pos.begin(), bf_pos.end(), delete_pos.begin(),
                 delete_pos.end(), inserter(remain_pos, remain_pos.begin()));
  // generate GGM Node for the remain position
  vector<GGMNode> node_list;
  node_list.reserve(remain_pos.size());
  for (long pos : remain_pos) {
    node_list.emplace_back(pos, tree->get_level());
  }
  vector<GGMNode> remain_node = tree->min_coverage(node_list);
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
  if (!server->search(token_str, remain_node, tree->get_level(), res)) {
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
  server->add_entries_batch(pending_entries);
  pending_entries.clear();
}