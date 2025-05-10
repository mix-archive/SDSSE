#ifndef FBDSSE_SDSSECQCLIENT_H
#define FBDSSE_SDSSECQCLIENT_H

#include <PBC.h>

#include "SSEClientHandler.h"

class SDSSECQClient {
private:
  // keys
  uint8_t *K = (unsigned char *)"0123456789123456";
  uint8_t *K_X = (unsigned char *)"0123456789123456";
  uint8_t *K_I = (unsigned char *)"0123456789654321";
  uint8_t *K_Z = (unsigned char *)"9876543210123456";
  uint8_t *iv = (unsigned char *)"9876543210123456";

  // pairing and GT element
  PBC::Pairing *e;
  PBC::GT *g;
  PBC::GPP<PBC::GT> *gpp;

  // SSE Instance
  SSEClientHandler *TEDB{};
  SSEClientHandler *XEDB{};

  // state map
  std::unordered_map<std::string, int> CT;

  PBC::Zr Fp(uint8_t *input, size_t input_size, uint8_t *key);

public:
  explicit SDSSECQClient(int ins_size, int del_size);
  void update(OP op, const std::string &keyword, int ind);
  std::vector<int> search(int count, ...);
  ~SDSSECQClient();
};

#endif // FBDSSE_SDSSECQCLIENT_H
