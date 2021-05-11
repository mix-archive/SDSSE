//
// Created by shangqi on 2021/4/20.
//

#ifndef FBDSSE_SDSSECQSSERVER_H
#define FBDSSE_SDSSECQSSERVER_H

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <string>
#include <unordered_map>
#include <PBC.h>

#include "BloomFilter.h"
extern "C" {
#include "CommonUtil.h"
}
#include "GGMTree.h"

using namespace std;

struct query_t_tuple {
    uint8_t *e_y;
    int search_count;
    int j;
};


class SDSSECQSServer {
private:
    unordered_map<string, string> tags;
    unordered_map<string, vector<string>> tmap;
    unordered_map<string, string> st_t;
    unordered_map<string, vector<string>> xmap;
    unordered_map<string, string> st_x;

    // cache
    unordered_map<string, unordered_map<string, query_t_tuple>> cache_t;
    unordered_map<string, unordered_map<string, GT>> cache_x;

    // pairing and GT element
    Pairing *e;

    static void compute_leaf_keys(unordered_map<long, uint8_t*>& keys, const vector<GGMNode>& node_list, int level);
    Zr Fp(uint8_t *input, size_t input_size, uint8_t *key);
    Zr Hp(uint8_t *input, size_t input_size);

public:
    explicit SDSSECQSServer(Pairing *e);
    void add_entries_in_TMap(const string& label, const string& tag, const string& st, vector<string>& ciphertext_list);
    void add_entries_in_XMap(const string& label, const string& tag, const string& st, vector<string>& ciphertext_list);
    vector<uint8_t*> search(int search_count, int level, int xterm_num,
                            uint8_t *k_wt, uint8_t *state_t, int counter_t, vector<GGMNode>& T_revoked_list, const string& t_token,
                            vector<uint8_t*>& k_wxs, vector<uint8_t*>& state_xs, vector<int>& counter_xs, vector<vector<GGMNode>>& X_revoked_list, vector<Zr>& xt_list, vector<vector<vector<GT>>>& xtoken_list, vector<string>& x_token_list);
};


#endif //FBDSSE_SDSSECQSERVER_H
