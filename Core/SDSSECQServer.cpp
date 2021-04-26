//
// Created by shangqi on 2021/4/20.
//

#include "SDSSECQServer.h"

Zr SDSSECQServer::Fp(uint8_t *input, size_t input_size, uint8_t *key) {
    uint8_t PRF[DIGEST_SIZE];
    hmac_digest(input, input_size,
                key, AES_BLOCK_SIZE,
                PRF);

    return Zr(*e, (void*) PRF, DIGEST_SIZE);
}

void SDSSECQServer::compute_leaf_keys(unordered_map<long, uint8_t*>& keys, const vector<GGMNode>& node_list, int level) {
    for(GGMNode node : node_list) {
        for (int i = 0; i < pow(2, level - node.level); ++i) {
            int offset = ((node.index) << (level - node.level)) + i;
            uint8_t derive_key[AES_BLOCK_SIZE];
            memcpy(derive_key, node.key, AES_BLOCK_SIZE);
            GGMTree::derive_key_from_tree(derive_key,  offset, level - node.level, 0);
            if(keys.find(offset) == keys.end()) {
                keys[offset] = (uint8_t*) malloc(AES_BLOCK_SIZE);
                memcpy(keys[offset], derive_key, AES_BLOCK_SIZE);
            }
        }
    }
}

SDSSECQServer::SDSSECQServer(Pairing *e) {
    this->e = e;
    tags.clear();
    tmap.clear();
    st_t.clear();
    xmap.clear();
    st_x.clear();
}

void SDSSECQServer::add_entries_in_TMap(const string& label, const string& tag, const string& st, vector<string>& ciphertext_list) {
    tags[label] = tag;
    st_t[label] = st;
    tmap[label] = move(ciphertext_list);
}

void SDSSECQServer::add_entries_in_XMap(const string& label, const string& tag, const string& st, vector<string>& ciphertext_list) {
    tags[label] = tag;
    st_x[label] = st;
    xmap[label] = move(ciphertext_list);
}

vector<uint8_t*> SDSSECQServer::search(int search_count, int level, int xterm_num, uint8_t *K_X,
                                       uint8_t *k_wt, uint8_t *state_t, int counter_t, vector<GGMNode>& T_revoked_list, const string& t_token,
                                       vector<uint8_t*>& k_wxs,  vector<uint8_t*>& state_xs, vector<int>& counter_xs, vector<vector<GGMNode>>& X_revoked_list, vector<vector<vector<GT>>>& xtoken_list, vector<string>& x_token_list) {
    // recover XSet for the search
    BloomFilter<128, XTAG_SIZE, XSET_HASH> xset;
    for(int i = 0; i < k_wxs.size(); i++) {
        // save the latest XMap state
        uint8_t ST_X_cur[DIGEST_SIZE];
        memcpy(ST_X_cur, state_xs[i], DIGEST_SIZE);
        // the extracted XSet
        unordered_map<string, GT> new_X, old_X, res_X;
        vector<string> del_X;
        for (int j = counter_xs[i]; j >= 0; j--) {
            // compute the label for XMap
            uint8_t XA_ST[DIGEST_SIZE];
            hmac_digest(ST_X_cur, DIGEST_SIZE,
                        k_wxs[i], DIGEST_SIZE,
                        XA_ST);
            string xmap_label_str((char*) XA_ST, DIGEST_SIZE);
            // extract the xmap state saved on server
            uint8_t x_server_state[DIGEST_SIZE];
            memcpy(x_server_state, (uint8_t*) st_x[xmap_label_str].c_str(), DIGEST_SIZE);
            // pre-search, derive all keys
            unordered_map<long, uint8_t*> keys;
            compute_leaf_keys(keys, X_revoked_list[i], level);
            // get the insert position of the tag
            vector<long> search_pos = BloomFilter<32, GGM_SIZE, HASH_SIZE>::get_index((uint8_t*) tags[xmap_label_str].c_str());
            sort(search_pos.begin(), search_pos.end());
            // derive the key from search position and decrypt the id
            vector<string> ciphertext_list = xmap[xmap_label_str];
            for (int k = 0; k < min(search_pos.size(), ciphertext_list.size()); k++) {
                auto xterm = (uint8_t*) malloc(ciphertext_list[k].size() - AES_BLOCK_SIZE);
                if(keys[search_pos[k]] != nullptr) { // if the key exists, then decrypt it
                    aes_decrypt((uint8_t *) (ciphertext_list[k].c_str() + AES_BLOCK_SIZE), ciphertext_list[k].size() - AES_BLOCK_SIZE,
                                keys[search_pos[k]], (uint8_t *) ciphertext_list[k].c_str(),
                                xterm);
                    // reconstruct xtag with xterm^r and store it in new_X
                    new_X[tags[xmap_label_str]] = GT(*e, xterm, ciphertext_list[k].size() - AES_BLOCK_SIZE)
                            ^ Fp(ST_X_cur, DIGEST_SIZE, K_X);
                    free(xterm);
                } else if(k < min(search_pos.size(), ciphertext_list.size()) - 1) {// the current key does not exist, but still can try the next key
                    continue;
                } else {    // the id is deleted
                    del_X.push_back(tags[xmap_label_str]);
                }
                break;
            }
            // update ST_X_cur
            transform(begin(XA_ST), end(XA_ST),
                      begin(x_server_state),
                      begin(ST_X_cur),
                      bit_xor<>());
            // free all keys for this cycle
            for(auto it : keys) {
                free(it.second);
            }
        }
        // try to update cache by remove all deleted tags
        old_X = cache_x[x_token_list[i]];
        for (const string& del_tag: del_X) {
            old_X.erase(del_tag);
        }
        // the new result consists of newly added tuples new_T and the remaining tuples old_T
        res_X.insert(old_X.begin(), old_X.end());
        res_X.insert(new_X.begin(), new_X.end());
        // cache the new result
        cache_x[x_token_list[i]] = res_X;
        // convert the res_X to a Bloom filter
        for(const auto& res : res_X) {
            xset.add_tag((uint8_t *) res.second.toString().c_str());
        }
    }
    // XSet is recovered
    // recover TSet for the search
    // save the latest TMap state
    uint8_t ST_T_cur[DIGEST_SIZE];
    memcpy(ST_T_cur, state_t, DIGEST_SIZE);
    // the extracted TSet
    unordered_map<string, query_t_tuple> new_T, old_T, res_T;
    vector<string> del_T;
    for (int i = counter_t; i >= 0; i--) {
        // compute the label for TMap
        uint8_t U_ST[DIGEST_SIZE];
        hmac_digest(ST_T_cur, DIGEST_SIZE,
                    k_wt, AES_BLOCK_SIZE,
                    U_ST);
        string tmap_label_str((char*) U_ST, DIGEST_SIZE);
        // extract the tmap state saved on server
        uint8_t t_server_state[DIGEST_SIZE];
        memcpy(t_server_state, (uint8_t*) st_t[tmap_label_str].c_str(), DIGEST_SIZE);
        // pre-search, derive all keys
        unordered_map<long, uint8_t*> keys;
        compute_leaf_keys(keys, T_revoked_list, level);
        // get the insert position of the tag
        vector<long> search_pos = BloomFilter<32, GGM_SIZE, HASH_SIZE>::get_index((uint8_t*) tags[tmap_label_str].c_str());
        sort(search_pos.begin(), search_pos.end());
        // derive the key from search position and decrypt the id
        vector<string> ciphertext_list = tmap[tmap_label_str];
        for (int j = 0; j < min(search_pos.size(), ciphertext_list.size()); j++) {
            auto res = (uint8_t*) malloc(ciphertext_list[j].size() - AES_BLOCK_SIZE);
            if(keys[search_pos[j]] != nullptr) { // if the key exists, then decrypt it and store in new_T
                aes_decrypt((uint8_t *) (ciphertext_list[j].c_str() + AES_BLOCK_SIZE), ciphertext_list[j].size() - AES_BLOCK_SIZE,
                            keys[search_pos[j]], (uint8_t *) ciphertext_list[j].c_str(),
                            res);
                new_T[tags[tmap_label_str]] = query_t_tuple{res, search_count, i};
            } else if(j < min(search_pos.size(), ciphertext_list.size()) - 1) {// the current key does not exist, but still can try the next key
                continue;
            } else {    // the id is deleted
                del_T.push_back(tags[tmap_label_str]);
            }
            break;
        }
        // update ST_T_cur
        transform(begin(U_ST), end(U_ST),
                  begin(t_server_state),
                  begin(ST_T_cur),
                  bit_xor<>());
        // free all keys for this cycle
        for(auto it : keys) {
            free(it.second);
        }
    }
    // try to update cache by remove all deleted tags
    old_T = cache_t[t_token];
    for (const string& del_tag: del_T) {
        free(old_T[del_tag].e_y);
        old_T.erase(del_tag);
    }
    // the new result consists of newly added tuples new_T and the remaining tuples old_T
    res_T.insert(old_T.begin(), old_T.end());
    res_T.insert(new_T.begin(), new_T.end());
    // cache the new result
    cache_t[t_token] = res_T;
    // TSet is recovered
    // try to fetch the final result
    vector<uint8_t*> res_list;
    for(const auto& it : res_T) {
        int counter = 0;
        // test whether the xtag exists or not
        for(int i = 0; i < xterm_num; i++) {
            Zr y = Zr(*e, it.second.e_y + AES_BLOCK_SIZE + sizeof(int), 20);
            uint8_t y_in_byte[element_length_in_bytes(const_cast<element_s *>(y.getElement()))];
            element_to_bytes(y_in_byte, const_cast<element_s *>(y.getElement()));
            GT tag = xtoken_list[it.second.search_count][it.second.j][i] ^ Zr(*e, it.second.e_y + AES_BLOCK_SIZE + sizeof(int), 20);
            if(xset.might_contain((uint8_t*) tag.toString().c_str())) {
                counter++;
            } else break;
        }
        // contain all xterms, this is a result
        if(counter == xterm_num) {
            // copy the result into res
            res_list.emplace_back(it.second.e_y);
        }
    }
    return res_list;
}