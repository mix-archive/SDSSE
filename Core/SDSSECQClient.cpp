//
// Created by shangqi on 2021/4/20.
//

#include "SDSSECQClient.h"

Zr SDSSECQClient::Fp(uint8_t *input, size_t input_size, uint8_t *key) {
    uint8_t PRF[DIGEST_SIZE];
    hmac_digest(input, input_size,
                key, AES_BLOCK_SIZE,
                PRF);

    return Zr(*e, (void*) PRF, DIGEST_SIZE);
}

Zr SDSSECQClient::Hp(uint8_t *input, size_t input_size) {
    uint8_t PRF[DIGEST_SIZE];
    sha256_digest(input, input_size, PRF);

    return Zr(*e, (void*) PRF, DIGEST_SIZE);
}

vector<GGMNode> SDSSECQClient::rev_key_generation(BloomFilter<DIGEST_SIZE, GGM_SIZE, HASH_SIZE>* deletion_map, uint8_t *key) {
    // search all deleted positions
    vector<long> bf_pos;
    for (int i = 0; i < GGM_SIZE; ++i) {
        bf_pos.emplace_back(i);
    }
    vector<long> delete_pos =deletion_map->search();
    vector<long> remain_pos;
    set_difference(bf_pos.begin(), bf_pos.end(),
                   delete_pos.begin(), delete_pos.end(),
                   inserter(remain_pos, remain_pos.begin()));
    // generate GGM Node for the remain position
    vector<GGMNode> node_list;
    node_list.reserve(remain_pos.size());
    for (long pos : remain_pos) {
        node_list.emplace_back(GGMNode(pos, tree->get_level()));
    }
    vector<GGMNode> remain_node = tree->min_coverage(node_list);
    for(auto & i : remain_node) {
        memcpy(i.key, key, AES_BLOCK_SIZE);
        GGMTree::derive_key_from_tree(i.key, i.index, i.level, 0);
    }
    return remain_node;
}

SDSSECQClient::SDSSECQClient() {
    tree = new GGMTree(GGM_SIZE);
    FILE *sysParamFile = fopen("pairing.param", "r");
    e = new Pairing(sysParamFile);
    fclose(sysParamFile);
    FILE  *saved_g = fopen("elliptic_g", "rw+");
    char s[8192];
    size_t count = fread(s, 1, 8192, saved_g);
    if(count) {
        element_t old_g;
        element_init_GT(old_g, const_cast<pairing_s *>(e->getPairing()));
        element_set_str(old_g, s, 2);
        uint8_t old_g_in_bytes[element_length_in_bytes(old_g)];
        element_to_bytes(old_g_in_bytes, old_g);
        g = GT(*e, old_g_in_bytes, sizeof(old_g_in_bytes));
    } else {
        g = GT(*e, false);
        element_out_str(saved_g, 2, const_cast<element_s *>(g.getElement()));
    }
    fclose(saved_g);
    server = new SDSSECQServer(e);
}

void SDSSECQClient::update(OP op, const string& keyword, int ind) {
    // if w is never inserted, initialise the deletion map and counter map
    // MSK_T is used as the indicator here;
    if (MSK_T.find(keyword) == MSK_T.end()) {
        // deletion map
        MSK_T[keyword] = new BloomFilter<DIGEST_SIZE, GGM_SIZE, HASH_SIZE>();
        MSK_X[keyword] = new BloomFilter<DIGEST_SIZE, GGM_SIZE, HASH_SIZE>();
        // counter map
        CT_T[keyword] = 0;
        CT_X[keyword] = 0;
    }
    // compute the tag (w||ind)
    uint8_t pair[keyword.size() + sizeof(int)];
    memcpy(pair, keyword.c_str(), keyword.size());
    memcpy(pair + keyword.size(), (uint8_t*) &ind, sizeof(int));
    // generate the tag PRF
    uint8_t tag[DIGEST_SIZE];
    hmac_digest(pair, keyword.size() + sizeof(int), K_t, AES_BLOCK_SIZE, tag);
    // process the operator
    if (op == INS) {
        // w_T = w||0||c_T
        uint8_t w_T[keyword.size() + 2 * sizeof(int)];
        // reset the buffer
        memset(w_T, 0, keyword.size() + 2 * sizeof(int));
        memcpy(w_T, keyword.c_str(), keyword.size());
        memcpy(w_T + keyword.size() + sizeof(int), (uint8_t*) &CT_T[keyword], sizeof(int));
        // generate the TMap key for w
        uint8_t K_wt[DIGEST_SIZE];
        hmac_digest(w_T, sizeof(w_T), K, AES_BLOCK_SIZE, K_wt);
        uint8_t *K_wt_2 = K_wt + AES_BLOCK_SIZE;
        // update the update map of TMap
        if (CT.find(string((const char*) w_T, sizeof(w_T))) == CT.end()) {
            CT[string((const char*) w_T, sizeof(w_T))] = -1;
            RAND_bytes(ST_T[string((const char*) w_T, sizeof(w_T))], DIGEST_SIZE);
        }
        // save the current ST_T value
        uint8_t ST_T_cur[DIGEST_SIZE];
        memcpy(ST_T_cur, ST_T[string((const char*) w_T, sizeof(w_T))], DIGEST_SIZE);
        // update CT and ST
        CT[string((const char*) w_T, sizeof(w_T))]++;
        RAND_bytes(ST_T[string((const char*) w_T, sizeof(w_T))], DIGEST_SIZE);
        // compute TMap tags
        uint8_t U_ST[DIGEST_SIZE];
        hmac_digest(ST_T[string((const char*) w_T, sizeof(w_T))], DIGEST_SIZE,
                    K_wt, AES_BLOCK_SIZE,
                    U_ST);
        // use XOR to chain tags
        uint8_t C_ST_CT[DIGEST_SIZE];
        transform(begin(U_ST), end(U_ST),
                  begin(ST_T_cur),
                  begin(C_ST_CT),
                  bit_xor<>());
        // encrypt the id
        uint8_t encrypted_id[AES_BLOCK_SIZE + sizeof(int)];
        memcpy(encrypted_id, iv, AES_BLOCK_SIZE);
        aes_encrypt((uint8_t*) &ind, sizeof(int),
                    K_wt_2, encrypted_id,
                    encrypted_id + AES_BLOCK_SIZE);
        // compute cross tags (xind=Fp(K_I, ind))
        Zr xind = Fp((uint8_t*) &ind, sizeof(int), K_I);
        // compute z=Fp(K_Z, w_T||CT+1)
        uint8_t Z_w_T[sizeof(w_T) + sizeof(int)];
        memcpy(Z_w_T, w_T, sizeof(w_T));
        memcpy(Z_w_T + sizeof(w_T), &CT[string((const char*) w_T, sizeof(w_T))], sizeof(int));
        Zr z = Fp(Z_w_T, sizeof(Z_w_T), K_Z);
        // y = xind * z^-1
        Zr y = xind / z;
        // concatenate e and y (e||y)
        // 1. convert element to byte array
        uint8_t y_in_byte[element_length_in_bytes(const_cast<element_s *>(y.getElement()))];
        element_to_bytes(y_in_byte, const_cast<element_s *>(y.getElement()));
        // 2. assign the array for the concatenation
        uint8_t ey[sizeof(encrypted_id) + sizeof(y_in_byte)];
        // 3. copy into the array
        memcpy(ey, encrypted_id, sizeof(encrypted_id));
        memcpy(ey + sizeof(encrypted_id), y_in_byte, sizeof(y_in_byte));
        // get all offsets in BF
        vector<long> indexes = BloomFilter<DIGEST_SIZE, GGM_SIZE, HASH_SIZE>::get_index(tag);
        sort(indexes.begin(), indexes.end());
        // get SRE ciphertext list for TMap
        vector<string> tuple_list;
        for(long index : indexes) {
            // derive a key from the offset
            uint8_t derived_key[AES_BLOCK_SIZE];
            memcpy(derived_key, sk_T, AES_BLOCK_SIZE);
            GGMTree::derive_key_from_tree(derived_key, index, tree->get_level(), 0);
            // use the key to encrypt e||y
            uint8_t encrypted_ey[AES_BLOCK_SIZE + sizeof(ey)];
            memcpy(encrypted_ey, iv, AES_BLOCK_SIZE);
            aes_encrypt(ey, sizeof(ey),
                        derived_key, encrypted_ey,
                        encrypted_ey + AES_BLOCK_SIZE);
            // save the encrypted e||y in the list
            tuple_list.emplace_back(string((char*) encrypted_ey, sizeof(encrypted_ey)));
        }
        // convert tag/label to string
        string tag_str((char*) tag, DIGEST_SIZE);
        string st_t_str((char*) C_ST_CT, DIGEST_SIZE);
        string tset_label_str((char*) U_ST, DIGEST_SIZE);
        // send T-tuple to server (UT, (tuple_// generate the key for wlist, C_ST_CT, tag))
        server->add_entries_in_TMap(tset_label_str, tag_str, st_t_str, tuple_list);
        // T-tuple done
        // w_X = w||1||c_X
        uint8_t w_X[keyword.size() + 2 * sizeof(int)];
        // reset the buffer
        memset(w_X, 1, keyword.size() + 2 * sizeof(int));
        memcpy(w_X, keyword.c_str(), keyword.size());
        memcpy(w_X + keyword.size() + sizeof(int), (uint8_t*) &CT_X[keyword], sizeof(int));
        // generate the XMap key for w
        uint8_t K_wx[DIGEST_SIZE];
        hmac_digest(w_X, sizeof(w_X), K, AES_BLOCK_SIZE, K_wx);
        // update the update map for XMap
        if (CX.find(string((const char*) w_X, sizeof(w_X))) == CX.end()) {
            CX[string((const char*) w_X, sizeof(w_X))] = -1;
            RAND_bytes(ST_X[string((const char*) w_X, sizeof(w_X))], DIGEST_SIZE);
        }
        // save the current ST_X value
        uint8_t ST_X_cur[DIGEST_SIZE];
        memcpy(ST_X_cur, ST_X[string((const char*) w_X, sizeof(w_X))], DIGEST_SIZE);
        // update CT and ST
        CX[string((const char*) w_X, sizeof(w_X))]++;
        RAND_bytes(ST_X[string((const char*) w_X, sizeof(w_X))], DIGEST_SIZE);
        // compute XMap tags
        uint8_t XA_ST[DIGEST_SIZE];
        hmac_digest(ST_X[string((const char*) w_X, sizeof(w_X))], DIGEST_SIZE,
                    K_wx, DIGEST_SIZE,
                    XA_ST);
        // use XOR to chain tags
        uint8_t C_ST_CX[DIGEST_SIZE];
        transform(begin(XA_ST), end(XA_ST),
                  begin(ST_X_cur),
                  begin(C_ST_CX),
                  bit_xor<>());
        // generate xterm=g^(Fp(K_X, w)*xind*r-1)
        GT xterm = g^(Fp((uint8_t*) keyword.c_str(), keyword.size(), K_X)
                * xind
                / Hp(ST_X[string((const char*) w_X, sizeof(w_X))], DIGEST_SIZE));
        // convert xterm to byte array
        uint8_t xterm_in_byte[element_length_in_bytes(const_cast<element_s *>(xterm.getElement()))];
        element_to_bytes(xterm_in_byte, const_cast<element_s *>(xterm.getElement()));
        // get SRE ciphertext list for XMap
        vector<string> xtag_list;
        for(long index : indexes) {
            // derive a key from the offset
            uint8_t derived_key[AES_BLOCK_SIZE];
            memcpy(derived_key, sk_X, AES_BLOCK_SIZE);
            GGMTree::derive_key_from_tree(derived_key, index, tree->get_level(), 0);
            // use the key to encrypt xterm
            uint8_t encrypted_xterm[AES_BLOCK_SIZE + sizeof(xterm_in_byte)];
            memcpy(encrypted_xterm, iv, AES_BLOCK_SIZE);
            aes_encrypt(xterm_in_byte, sizeof(xterm_in_byte),
                        derived_key, encrypted_xterm,
                        encrypted_xterm + AES_BLOCK_SIZE);
            // save the encrypted e||y in the list
            xtag_list.emplace_back(string((char*) encrypted_xterm, sizeof(encrypted_xterm)));
        }
        // send xtags to server (XA, (xtag_list, C_ST_CX, tag))
        string st_x_str((char*) C_ST_CX, DIGEST_SIZE);
        string xmap_label_str((char*) XA_ST, DIGEST_SIZE);
        // send T-tuple to server (UT, (tuple_list, C_ST_CT, tag))
        server->add_entries_in_XMap(xmap_label_str, tag_str, st_x_str, xtag_list);
    } else {
        // insert the tag into the deletion map
        MSK_T[keyword]->add_tag(tag);
        MSK_X[keyword]->add_tag(tag);
    }
}

vector<int> SDSSECQClient::search(int count, ...) {
    vector<int> res;
    // keys to be generated
    uint8_t K_wt[DIGEST_SIZE];              // TMap key
    uint8_t *K_wt_2;                        // TMap key for id
    vector<uint8_t*> K_wxs;                 // XMap keys
    // revoked key list
    vector<GGMNode> T_revoked_key_list;             // revoked key for TMap
    vector<vector<GGMNode>> X_revoked_key_lists;     // revoked key for XMap
    // XMap state and counter list
    vector<uint8_t*> state_xs;
    vector<int> count_xs;
    // xtoken list
    vector<vector<vector<GT>>> xtoken_list;         // xtoken list (GT element list)
    // cache tokens
    string token_T_str;                             // the token for TMap cache
    vector<string> token_X_str_list;                // the token list for XMap cache
    // start to read the keyword list
    va_list keyword_list;
    va_start(keyword_list, count);
    string sterm = string(va_arg(keyword_list, char*));
    // if sterm is never inserted, return an empty vector
    if (CT_T.find(sterm) == CT_T.end()) {
        return vector<int>();
    }
    // save the current counter
    int sterm_search_count = CT_T[sterm];
    // compute the token for TMap (sterm||0)
    uint8_t pair_T[sterm.size() + sizeof(int)];
    memset(pair_T, 0, sizeof(pair_T));
    memcpy(pair_T, sterm.c_str(), sterm.size());
    // generate the token PRF
    uint8_t token_T[DIGEST_SIZE];
    hmac_digest(pair_T, sizeof(pair_T), K_s, AES_BLOCK_SIZE, token_T);
    token_T_str = string((const char*) token_T, DIGEST_SIZE);
    // compute the SRE keys from the deletion map
    T_revoked_key_list = rev_key_generation(MSK_T[sterm], sk_T);
    // reset deletion map
    MSK_T[sterm]->reset();
    // update search counter
    CT_T[sterm]++;
    // w_T = w||0||c_T
    uint8_t w_T[sterm.size() + 2 * sizeof(int)];
    // reset the buffer
    memset(w_T, 0, sterm.size() + 2 * sizeof(int));
    memcpy(w_T, sterm.c_str(), sterm.size());
    memcpy(w_T + sterm.size() + sizeof(int), (uint8_t*) &sterm_search_count, sizeof(int));
    // generate the TMap key for sterm
    hmac_digest(w_T, sizeof(w_T), K, AES_BLOCK_SIZE, K_wt);
    K_wt_2 = K_wt + AES_BLOCK_SIZE;
    // read all xterms
    vector<string> xterms;
    for (int i = 1; i < count; i++) {
        xterms.emplace_back(string(va_arg(keyword_list, char*)));
    }
    // generate the revocation key for each xterm
    for(const string& xterm : xterms) {
        // if xterm is never inserted, return an empty vector
        if(CT_X.find(xterm) == CT_X.end()) {
            return vector<int>();
        }
        // save the current counter
        int xterm_search_count = CT_X[xterm];
        // compute the token for XMap (xterm||1)
        uint8_t pair_X[sterm.size() + sizeof(int)];
        memset(pair_X, 0, sizeof(pair_X));
        memcpy(pair_X, xterm.c_str(), xterm.size());
        // generate the token PRF
        uint8_t token_X[DIGEST_SIZE];
        hmac_digest(pair_X, sizeof(pair_X), K_s, AES_BLOCK_SIZE, token_X);
        string token_X_str = string((const char*) token_X, DIGEST_SIZE);
        token_X_str_list.emplace_back(token_X_str);
        // compute the SRE keys from the deletion map
        X_revoked_key_lists.emplace_back(rev_key_generation(MSK_X[xterm], sk_X));
        // reset deletion map
        MSK_X[xterm]->reset();
        // update search counter
        CT_X[xterm]++;
        // w_X = w||1||c_T
        uint8_t w_X[xterm.size() + 2 * sizeof(int)];
        // reset the buffer
        memset(w_X, 1, xterm.size() + 2 * sizeof(int));
        memcpy(w_X, xterm.c_str(), xterm.size());
        memcpy(w_X + xterm.size() + sizeof(int), (uint8_t*) &xterm_search_count, sizeof(int));
        // generate the XMap key for the current xterm
        uint8_t K_wx[DIGEST_SIZE];
        hmac_digest(w_X, sizeof(w_X), K, AES_BLOCK_SIZE, K_wx);
        K_wxs.push_back(K_wx);
        // get state and counter of the current xterm
        state_xs.emplace_back(ST_X[string((const char*) w_X, sizeof(w_X))]);
        count_xs.emplace_back(CX[string((const char*) w_X, sizeof(w_X))]);
    }
    for (int i = 0; i <= sterm_search_count; i++) {
        // w_T_i=w||0||i
        uint8_t w_T_i[sterm.size() + 2 * sizeof(int)];
        // reset the buffer
        memset(w_T_i, 0, sterm.size() + 2 * sizeof(int));
        memcpy(w_T_i, sterm.c_str(), sterm.size());
        memcpy(w_T_i + sterm.size() + sizeof(int), (uint8_t*) &i, sizeof(int));
        // get the update count
        int sterm_update_count = CT[string((const char*)w_T_i, sizeof(w_T_i))];
        // compute the xtokens for this update
        vector<vector<GT>> token_i_j;
        for (int j = 0; j <= sterm_update_count; j++) {
            vector<GT> token_j;
            for(const string& xterm : xterms) {
                // compute z=Fp(K_Z, w||0||i||j)
                uint8_t Z_w_T_i[sizeof(w_T_i) + sizeof(int)];
                memcpy(Z_w_T_i, w_T_i, sizeof(w_T_i));
                memcpy(Z_w_T_i + sizeof(w_T_i), &j, sizeof(int));
                Zr z = Fp(Z_w_T_i, sizeof(Z_w_T_i), K_Z);
                token_j.emplace_back(g ^ (z * Fp((uint8_t*) xterm.c_str(), xterm.size(), K_X)));
            }
            token_i_j.emplace_back(token_j);
        }
        xtoken_list.emplace_back(token_i_j);
    }
    va_end(keyword_list);
    // send all tokens to the server and retrieve tuples
    vector<uint8_t*> encrypted_res_list =
            server->search(sterm_search_count, tree->get_level(), xterms.size(),
                           K_wt,
                           ST_T[string((const char*) w_T, sizeof(w_T))],CT[string((const char*) w_T, sizeof(w_T))],
                           T_revoked_key_list,
                           token_T_str,
                           K_wxs,
                           state_xs,count_xs,
                           X_revoked_key_lists, xtoken_list,
                           token_X_str_list);
    // decrypt e locally
    for (auto encyrpted_res : encrypted_res_list) {
        int ind;
        aes_decrypt(encyrpted_res + AES_BLOCK_SIZE, sizeof(int),
                K_wt_2, encyrpted_res,
                (uint8_t*)&ind);
        res.push_back(ind);
        free(encyrpted_res);
    }
    return res;
}


