#ifndef AURA_SSECLIENTHANDLER_H
#define AURA_SSECLIENTHANDLER_H

#include "Core/SSEServerHandler.h"

enum OP {
    INS, DEL
};

class SSEClientHandler {
private:
    uint8_t *key = (unsigned char*) "0123456789123456";
    uint8_t *iv = (unsigned char*) "0123456789123456";

    GGMTree *tree;
    int GGM_SIZE;
    BloomFilter<32, HASH_SIZE> *delete_bf;
    unordered_map<string, int> C;       // search time

    SSEServerHandler *server;
public:
    SSEClientHandler(int del_size);
    ~SSEClientHandler();
    void update(OP op, const string& keyword, int ind, uint8_t* content, size_t content_len);
    vector<string> search(const string& keyword);
};


#endif //AURA_SSECLIENTHANDLER_H
