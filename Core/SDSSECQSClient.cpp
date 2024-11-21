#include "SDSSECQSClient.h"

Zr SDSSECQSClient::Fp(uint8_t *input, size_t input_size, uint8_t *key) {
    uint8_t PRF[DIGEST_SIZE];
    hmac_digest(input, input_size,
                key, AES_BLOCK_SIZE,
                PRF);

    return Zr(*e, (void*) PRF, DIGEST_SIZE);
}


SDSSECQSClient::SDSSECQSClient(int del_size) {
    // generate or load pairing
    FILE *sysParamFile = fopen("pairing.param", "r");
    e = new Pairing(sysParamFile);
    fclose(sysParamFile);
    // try to load the saved group
    FILE  *saved_g = fopen("elliptic_g", "rw+");
    char s[8192];
    size_t count = fread(s, 1, 8192, saved_g);
    if(count) {
        element_t old_g;
        element_init_GT(old_g, const_cast<pairing_s *>(e->getPairing()));
        element_set_str(old_g, s, 2);
        uint8_t old_g_in_bytes[element_length_in_bytes(old_g)];
        element_to_bytes(old_g_in_bytes, old_g);
        g = new GT(*e, old_g_in_bytes, sizeof(old_g_in_bytes));
        gpp = new GPP<GT>(*e, *g);
    } else {
        // a new group is required
        g = new GT(*e, false);
        gpp = new GPP<GT>(*e, *g);
        element_out_str(saved_g, 2, const_cast<element_s *>(g->getElement()));
    }
    fclose(saved_g);

    // initialise SSE instance
    TEDB = new SSEClientHandler(del_size);
    XEDB = new SSEClientHandler(del_size);
}

void SDSSECQSClient::update(OP op, const string& keyword, int ind) {
    // if w is never inserted, initialise the deletion map and counter map
    // MSK_T is used as the indicator here;
    if (CT.find(keyword) == CT.end()) {
        // counter map
        CT[keyword] = -1;
    }
    // update CT
    int c = CT[keyword] + 1;
    CT[keyword] = c;

    // generate the key for w
    uint8_t K_w[DIGEST_SIZE];
    hmac_digest((unsigned char *) keyword.c_str(), keyword.size(), K, AES_BLOCK_SIZE, K_w);

    // compute TSet values
    // encrypt the id
    uint8_t encrypted_id[AES_BLOCK_SIZE + sizeof(int)];
    memcpy(encrypted_id, iv, AES_BLOCK_SIZE);
    aes_encrypt((uint8_t*) &ind, sizeof(int),
                K_w, encrypted_id,
                encrypted_id + AES_BLOCK_SIZE);
    // compute cross tags (xind=Fp(K_I, ind))
    Zr xind = Fp((uint8_t*) &ind, sizeof(int), K_I);
    // compute z=Fp(K_Z, w||c)
    uint8_t Z_w[keyword.size() + sizeof(int)];
    memcpy(Z_w,  keyword.c_str(), keyword.size());
    memcpy(Z_w + keyword.size(), &CT[keyword], sizeof(int));
    Zr z = Fp(Z_w, sizeof(Z_w), K_Z);
    // y = xind * z^-1
    Zr y = xind / z;
    // concatenate e, y and c
    // 1. convert element to byte array
    uint8_t y_in_byte[element_length_in_bytes(const_cast<element_s *>(y.getElement()))];
    element_to_bytes(y_in_byte, const_cast<element_s *>(y.getElement()));
    // 2. assign the array for the concatenation
    uint8_t eyc[sizeof(encrypted_id) + sizeof(y_in_byte) + sizeof(int)];
    // 3. copy into the array
    memcpy(eyc, encrypted_id, sizeof(encrypted_id));
    memcpy(eyc + sizeof(encrypted_id), y_in_byte, sizeof(y_in_byte));
    memcpy(eyc + sizeof(encrypted_id) + sizeof(y_in_byte), &c, sizeof(int));
    // upload to TEDB
    TEDB->update(op, keyword, ind, eyc, sizeof(eyc));

    // generate xterm=g^(Fp(K_X, w)*xind)
    GT wxtag = (*gpp)^(Fp((uint8_t*) keyword.c_str(), keyword.size(), K_X)
                      * xind / Fp((uint8_t*) Z_w, sizeof(Z_w), K_x));
    uint8_t wxtag_in_byte[element_length_in_bytes(const_cast<element_s *>(wxtag.getElement())) + sizeof(int)];
    element_to_bytes(wxtag_in_byte, const_cast<element_s *>(wxtag.getElement()));
    memcpy(wxtag_in_byte + element_length_in_bytes(const_cast<element_s *>(wxtag.getElement())), &c, sizeof(int));
    // upload to XEDB
    XEDB->update(op, keyword, ind, wxtag_in_byte, sizeof(wxtag_in_byte));
}

vector<int> SDSSECQSClient::search(int count, ...) {
    vector<int> res;
    // xtoken list
    vector<vector<GT>> wxtoken_list;         // xtoken list (GT element list)
    vector<vector<Zr>> zxtoken_list;         // wxp list (Zr element list)

    // start to read the keyword list
    va_list keyword_list;
    va_start(keyword_list, count);
    string sterm = string(va_arg(keyword_list, char*));
    // if sterm is never inserted, return an empty vector
    if (CT.find(sterm) == CT.end()) {
        return {};
    }
    // read all xterms
    vector<string> xterms;
    if(count > 1) {
        for (int i = 1; i < count; i++) {
            xterms.emplace_back(va_arg(keyword_list, char*));
        }
        // compute wxtokens
        for (int i = 0; i <= CT[sterm]; i++) {
            // w_i=w||i
            uint8_t w_i[sterm.size() + sizeof(int)];
            // reset the buffer
            memset(w_i, 0, sterm.size() + sizeof(int));
            memcpy(w_i, sterm.c_str(), sterm.size());
            memcpy(w_i + sterm.size(), (uint8_t *) &i, sizeof(int));
            // compute the xtokens for this update
            vector<GT> token_i;
            // compute z=Fp(K_Z, w||i)
            Zr z = Fp(w_i, sizeof(w_i), K_Z);
            for (const string &xterm: xterms) {
                token_i.emplace_back((*gpp) ^ (z * Fp((uint8_t *) xterm.c_str(), xterm.size(), K_X)
                                               * Fp((uint8_t *) sterm.c_str(), sterm.size(), K_z)));
                // if xterm is never inserted, return an empty vector
                if (CT.find(xterm) == CT.end()) {
                    return {};
                }
                vector<Zr> zx_i;
                for (int k = 0; k <= CT[xterm]; k++) {
                    // w_j=w||j
                    uint8_t w_j[xterm.size() + sizeof(int)];
                    // reset the buffer
                    memset(w_j, 0, xterm.size() + sizeof(int));
                    memcpy(w_j, xterm.c_str(), xterm.size());
                    memcpy(w_j + xterm.size(), (uint8_t *) &k, sizeof(int));
                    zx_i.emplace_back(Fp(w_j, sizeof(w_j), K_x)
                                      * Fp((uint8_t *) sterm.c_str(), sterm.size(), K_z));
                }
                zxtoken_list.emplace_back(zx_i);
            }
            wxtoken_list.emplace_back(token_i);
        }
    }
    va_end(keyword_list);

    // invoke search (server part)
    // 1. query TEDB for TSets
    vector<string> Res_T = TEDB->search(sterm);
    if(Res_T.empty()) {
        return {};
    }

    // 2. query XEDB for XSets
    BloomFilter<128, XSET_HASH> Res_WX(XSET_SIZE);
    for(int j = 1; j < count; j++) {
        vector<string> Res_wxtags = XEDB->search(xterms[j - 1]);
        // if any of the xterm cannot be found, search end, no conjunction
        if(Res_wxtags.empty()) {
            return {};
        }
        for(const auto& wxtag_string : Res_wxtags) {
            GT tag = GT(*e, reinterpret_cast<const unsigned char *>(wxtag_string.c_str()), 128)
                    ^ zxtoken_list[j - 1][*((int*)(wxtag_string.c_str() + 128))];
            Res_WX.add_tag((uint8_t *) tag.toString().c_str());
        }
    }

    // 3. search intersections in TSet
    vector<uint8*> encrypted_res_list;
    for(const string& t_tuple : Res_T) {
        auto flag = true;
        Zr y = Zr(*e, t_tuple.c_str() + AES_BLOCK_SIZE + sizeof(int), 20);
        for(int j = 1; j < count; j++) {
            GT tag = wxtoken_list[*(int*)(t_tuple.c_str() + AES_BLOCK_SIZE + sizeof(int) + 20)][j - 1] ^ y;
            if(!Res_WX.might_contain((uint8_t*) tag.toString().c_str())) {
                flag = false;
                break;
            }
        }
        if(flag) {
            // add to res set
            encrypted_res_list.emplace_back((uint8*) t_tuple.c_str());
        }
    }

    // decrypt e locally
    // generate the key for sterm
    uint8_t K_w[DIGEST_SIZE];
    hmac_digest((unsigned char *) sterm.c_str(), sterm.size(), K, AES_BLOCK_SIZE, K_w);
    for (auto encrypted_res : encrypted_res_list) {
        int ind;
        aes_decrypt(encrypted_res + AES_BLOCK_SIZE, sizeof(int),
                    K_w, encrypted_res,
                    (uint8_t*)&ind);
        res.push_back(ind);
    }
    return res;
}


