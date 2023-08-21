//
// Created by shangqi on 2020/6/17.
//

#include "Core/SSEServerHandler.h"

SSEServerHandler::SSEServerHandler() {
    tags.clear();
    dict.clear();
}

void SSEServerHandler::add_entries(const string& label, const string& tag, vector<string> ciphertext_list) {
    tags[label] = tag;
    dict[label] = move(ciphertext_list);
}

vector<string> SSEServerHandler::search(uint8_t *token, const vector<GGMNode>& node_list, int level) {
    keys.clear();
    root_key_map.clear();
    // pre-search, derive all keys
    compute_leaf_key_maps(node_list, level);
    // get the result
    int counter = 0;
    vector<string> res_list;
    while (true) {
        // get label string
        uint8_t label[DIGEST_SIZE];
        hmac_digest((uint8_t*) &counter, sizeof(int),
                    token, DIGEST_SIZE,
                    label);
        string label_str((char*) label, DIGEST_SIZE);
        counter++;
        // terminate if no label
        if(tags.find(label_str) == tags.end()) break;
        // get the insert position of the tag
        vector<long> search_pos = BloomFilter<32, GGM_SIZE, HASH_SIZE>::get_index((uint8_t*) tags[label_str].c_str());
        sort(search_pos.begin(), search_pos.end());
        // derive the key from search position and decrypt the id
        vector<string> ciphertext_list = dict[label_str];
        for (int i = 0; i < min(search_pos.size(), ciphertext_list.size()); ++i) {
            uint8_t res[ciphertext_list[i].size() - AES_BLOCK_SIZE];
            if(root_key_map.find(search_pos[i]) == root_key_map.end()) break;
            // derive key for the search position
            uint8_t derive_key[AES_BLOCK_SIZE];
            memcpy(derive_key, node_list[root_key_map[search_pos[i]]].key, AES_BLOCK_SIZE);
            GGMTree::derive_key_from_tree(derive_key,  search_pos[i], level - node_list[root_key_map[search_pos[i]]].level, 0);
            int size = aes_decrypt((uint8_t *) (ciphertext_list[i].c_str() + AES_BLOCK_SIZE), ciphertext_list[i].size() - AES_BLOCK_SIZE,
                                   derive_key, (uint8_t *) ciphertext_list[i].c_str(),
                        res);
            if(size > 0) {
                res_list.emplace_back(string(reinterpret_cast<const char *>(res), ciphertext_list[i].size() - AES_BLOCK_SIZE));
            }
            break;
        }
    }
    return res_list;
}

void SSEServerHandler::compute_leaf_key_maps(const vector<GGMNode>& node_list, int level) {
    for(int i = 0; i < node_list.size(); i++) {
        for (long j = 0; j < pow(2, level - node_list[i].level); ++j) {
            long offset = ((node_list[i].index) << (level - node_list[i].level)) + j;
            root_key_map[offset] = i;
        }
    }
}