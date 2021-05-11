//
// Created by shangqi on 2021/4/20.
//

#ifndef FBDSSE_VSDSSECQSERVER_H
#define FBDSSE_VSDSSECQSERVER_H

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <string>
#include <unordered_set>
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

struct verify_t_tuple {
    int k;
    mpz_t a;
    mpz_t b;
    uint8_t *e_y;
};

static void hash_to_prime(mpz_t *res, uint8_t *string, size_t size) {
    int is_prime = 0;
    uint8_t prime_byte[DIGEST_SIZE];
    sha256_digest(string, size, prime_byte);
    int r = 0;
    while (!is_prime) {
        uint8_t hash_r[DIGEST_SIZE];
        sha256_digest((uint8_t*) &r, sizeof(int), hash_r);
        memcpy(prime_byte + DIGEST_SIZE / 2, hash_r, DIGEST_SIZE / 2);
        mpz_import(*res, DIGEST_SIZE, 1, 1, 0, 0, prime_byte);
        if(!mpz_probab_prime_p(*res, 15)) {
            r++;
        } else {
            is_prime = 1;
        }
    }
}

class VSDSSECQServer {
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
    explicit VSDSSECQServer(Pairing *e);
    void add_entries_in_TMap(const string& label, const string& tag, const string& st, vector<string>& ciphertext_list);
    void add_entries_in_XMap(const string& label, const string& tag, const string& st, vector<string>& ciphertext_list);
    void search(vector<verify_t_tuple> &res_v, vector<uint8_t*> &res_e,
            int search_count, int level, int xterm_num,
                            uint8_t *k_wt, uint8_t *state_t, int counter_t, vector<GGMNode>& T_revoked_list, const string& t_token,
                            vector<uint8_t*>& k_wxs, vector<uint8_t*>& state_xs, vector<int>& counter_xs, vector<vector<GGMNode>>& X_revoked_list, vector<vector<vector<GT>>>& xtoken_list, vector<string>& x_token_list);
};


#endif //FBDSSE_SDSSECQSERVER_H
