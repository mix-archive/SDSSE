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
  std::unique_ptr<PBC::Pairing> e;
  std::unique_ptr<PBC::GT> g;
  std::unique_ptr<PBC::GPP<PBC::GT>> gpp;

  // SSE Instance
  SSEClientHandler TEDB;
  SSEClientHandler XEDB;

  // state map
  std::unordered_map<std::string, int> CT;

  PBC::Zr Fp(uint8_t *input, size_t input_size, uint8_t *key);

public:
  SDSSECQSClient(int ins_size, int del_size, bool init_remote = true);
  ~SDSSECQSClient() { flush(); }

  void update(UpdateOP op, const std::string &keyword, int ind);
  std::vector<int> search(const std::vector<std::string> &keywords);

  // Load keyword counter map (CT) from external source, replacing existing
  // entries. Each value should be (number_of_insertions_for_keyword - 1).
  void load_CT(const std::unordered_map<std::string, int> &ct_map) {
    CT = ct_map;
  }

  // Force flush pending insertions to server.
  void flush() {
    TEDB.flush();
    XEDB.flush();
  }
};

#endif // FBDSSE_SDSSECQCLIENT_H
