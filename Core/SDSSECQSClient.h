#ifndef FBDSSE_SDSSECQSCLIENT_H
#define FBDSSE_SDSSECQSCLIENT_H

#include <PBC.h>

#include "SSEClientHandler.h"

class SDSSECQSClient {
private:
  // keys
  uint8_t *K = (unsigned char *)"0123456789123456";
  uint8_t *K_s = (unsigned char *)"0123456789654321";
  uint8_t *K_t = (unsigned char *)"9876543210123456";
  uint8_t *K_X = (unsigned char *)"0123456789123456";
  uint8_t *K_x = (unsigned char *)"0123456789654321";
  uint8_t *K_I = (unsigned char *)"0123456789123456";
  uint8_t *K_Z = (unsigned char *)"0123456789654321";
  uint8_t *K_z = (unsigned char *)"9876543210123456";
  uint8_t *sk_T = (unsigned char *)"0123456789123456";
  uint8_t *sk_X = (unsigned char *)"0123456789654321";
  uint8_t *iv = (unsigned char *)"9876543210123456";

  // pairing and GT element
  Pairing *e;
  GT *g;
  GPP<GT> *gpp;

  // SSE Instance
  SSEClientHandler *TEDB;
  SSEClientHandler *XEDB;

  // state map
  unordered_map<string, int> CT;

  Zr Fp(uint8_t *input, size_t input_size, uint8_t *key);

public:
  explicit SDSSECQSClient(int ins_size, int del_size);
  void update(OP op, const string &keyword, int ind);
  vector<int> search(int count, ...);
};

#endif // FBDSSE_SDSSECQCLIENT_H
