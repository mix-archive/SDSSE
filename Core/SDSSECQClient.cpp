#include "SDSSECQClient.h"
#include "Pairing.h"
#include <pbc/pbc.h>

using PBC::Zr, PBC::GT, PBC::GPP, PBC::Pairing;
using std::vector, std::string;

Zr SDSSECQClient::Fp(uint8_t *input, size_t input_size, uint8_t *key) {
  uint8_t PRF[DIGEST_SIZE];
  hmac_digest(input, input_size, key, SM4_BLOCK_SIZE, PRF);

  return Zr(*e, (void *)PRF, DIGEST_SIZE);
}

SDSSECQClient::SDSSECQClient(int ins_size, int del_size, bool init_remote)
    : TEDB(ins_size, del_size, "tedb", init_remote),
      XEDB(ins_size, del_size, "xedb", init_remote) {
  // generate or load pairing parameters. If pairing.param does not exist,
  // generate default Type A parameters (rbits=160, qbits=512).
  FILE *sysParamFile = fopen("pairing.param", "r");
  if (!sysParamFile) {
    FILE *paramOut = fopen("pairing.param", "w");
    if (!paramOut) {
      fprintf(stderr, "[SDSSECQClient] Cannot create pairing.param file.\n");
      throw std::runtime_error("failed to create pairing.param");
    }
    pbc_param_t p;
    pbc_param_init_a_gen(p, 160, 512);
    pbc_param_out_str(paramOut, p);
    pbc_param_clear(p);
    fclose(paramOut);
    sysParamFile = fopen("pairing.param", "r");
  }
  e = std::make_unique<Pairing>(sysParamFile);
  fclose(sysParamFile);
  // try to load the saved group
  FILE *saved_g = fopen("elliptic_g", "rw+");
  char s[8192];
  size_t count = fread(s, 1, 8192, saved_g);
  if (count) {
    element_t old_g;
    element_init_GT(old_g, const_cast<pairing_s *>(e->getPairing()));
    element_set_str(old_g, s, 2);
    vector<uint8_t> old_g_in_bytes(element_length_in_bytes(old_g));
    element_to_bytes(old_g_in_bytes.data(), old_g);
    g = std::make_unique<GT>(*e, old_g_in_bytes.data(), old_g_in_bytes.size());
    gpp = std::make_unique<GPP<GT>>(*e, *g);
  } else {
    // a new group is required
    g = std::make_unique<GT>(*e, false);
    gpp = std::make_unique<GPP<GT>>(*e, *g);
    element_out_str(saved_g, 2, const_cast<element_s *>(g->getElement()));
  }
  fclose(saved_g);
}

void SDSSECQClient::update(UpdateOP op, const string &keyword, int ind) {
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
  hmac_digest((unsigned char *)keyword.c_str(), keyword.size(), K,
              SM4_BLOCK_SIZE, K_w);

  // compute TSet values
  // encrypt the id
  uint8_t encrypted_id[SM4_BLOCK_SIZE + sizeof(int)];
  memcpy(encrypted_id, iv, SM4_BLOCK_SIZE);
  sm4_encrypt((uint8_t *)&ind, sizeof(int), K_w, encrypted_id,
              encrypted_id + SM4_BLOCK_SIZE);
  // compute cross tags (xind=Fp(K_I, ind))
  Zr xind = Fp((uint8_t *)&ind, sizeof(int), K_I);
  // compute z=Fp(K_Z, w||c)
  vector<uint8_t> Z_w(keyword.size() + sizeof(int));
  memcpy(Z_w.data(), keyword.c_str(), keyword.size());
  memcpy(Z_w.data() + keyword.size(), &CT[keyword], sizeof(int));
  Zr z = Fp(Z_w.data(), Z_w.size(), K_Z);
  // y = xind * z^-1
  Zr y = xind / z;
  // concatenate e, y and c
  // 1. convert element to byte array
  vector<uint8_t> y_in_byte(
      element_length_in_bytes(const_cast<element_s *>(y.getElement())));
  element_to_bytes(y_in_byte.data(), const_cast<element_s *>(y.getElement()));
  // 2. assign the array for the concatenation
  vector<uint8_t> eyc(sizeof(encrypted_id) + y_in_byte.size() + sizeof(int));
  // 3. copy into the array
  memcpy(eyc.data(), encrypted_id, sizeof(encrypted_id));
  memcpy(eyc.data() + sizeof(encrypted_id), y_in_byte.data(), y_in_byte.size());
  memcpy(eyc.data() + sizeof(encrypted_id) + y_in_byte.size(), &CT[keyword],
         sizeof(int));
  // upload to TEDB
  TEDB.update(op, keyword, ind, eyc.data(), eyc.size());

  // generate xterm=g^(Fp(K_X, w)*xind)
  GT xtag =
      (*gpp) ^ (Fp((uint8_t *)keyword.c_str(), keyword.size(), K_X) * xind);
  // upload to XEDB
  XEDB.update(op, keyword, ind, (uint8_t *)xtag.toString().c_str(),
              xtag.toString().size());
}

std::vector<int>
SDSSECQClient::search(const std::vector<std::string> &keywords) {
  std::vector<int> res;

  if (keywords.empty()) {
    return res;
  }

  const std::string &sterm = keywords[0];

  // if sterm is never inserted, return an empty vector
  if (CT.find(sterm) == CT.end()) {
    return res;
  }

  // separate conjunctive terms (if any)
  std::vector<std::string> xterms;
  if (keywords.size() > 1) {
    xterms.assign(keywords.begin() + 1, keywords.end());
  }

  // ------------------------------------------------------------------
  // 1. Pre-compute xtokens (client side)
  // ------------------------------------------------------------------
  std::vector<std::vector<GT>> xtoken_list; // xtoken list (GT element list)
  if (!xterms.empty()) {
    for (int i = 0; i <= CT[sterm]; ++i) {
      // w_i = w || i
      std::vector<uint8_t> w_i(sterm.size() + sizeof(int));
      memset(w_i.data(), 0, w_i.size());
      memcpy(w_i.data(), sterm.c_str(), sterm.size());
      memcpy(w_i.data() + sterm.size(), &i, sizeof(int));

      // z = Fp(K_Z, w||i)
      Zr z = Fp(w_i.data(), w_i.size(), K_Z);

      std::vector<GT> token_i(xterms.size());
      for (size_t j = 0; j < xterms.size(); ++j) {
        auto &xterm = xterms[j];
        token_i[j] =
            (*gpp) ^ (z * Fp((uint8_t *)xterm.c_str(), xterm.size(), K_X));
      }
      xtoken_list.emplace_back(std::move(token_i));
    }
  }

  // ------------------------------------------------------------------
  // 2. Query TEDB for TSet
  // ------------------------------------------------------------------
  auto Res_T = TEDB.search(sterm);
  if (Res_T.empty()) {
    return res;
  }

  // ------------------------------------------------------------------
  // 3. Query XEDB for XSet (if conjunctive search)
  // ------------------------------------------------------------------
  int XSET_SIZE = get_BF_size(XSET_HASH, MAX_DB_SIZE, XSET_FP);
  BloomFilter<128, XSET_HASH> Res_X(XSET_SIZE);
  for (const std::string &xterm : xterms) {
    auto Res_xtags = XEDB.search(xterm);
    // if any of the xterm cannot be found, search ends (empty intersection)
    if (Res_xtags.empty()) {
      return res;
    }
    for (const auto &xtag_string : Res_xtags) {
      Res_X.add_tag((uint8_t *)xtag_string.c_str());
    }
  }

  // ------------------------------------------------------------------
  // 4. Intersect results
  // ------------------------------------------------------------------
  std::vector<uint8 *> encrypted_res_list;
  for (const std::string &t_tuple : Res_T) {
    bool flag = true;
    Zr y = Zr(*e, t_tuple.c_str() + SM4_BLOCK_SIZE + sizeof(int), 20);
    for (size_t j = 0; j < xterms.size(); ++j) {
      auto tag = xtoken_list[*reinterpret_cast<const int *>(
                     t_tuple.c_str() + SM4_BLOCK_SIZE + sizeof(int) + 20)][j] ^
                 y;
      if (!Res_X.might_contain((uint8_t *)tag.toString().c_str())) {
        flag = false;
        break;
      }
    }
    if (flag) {
      encrypted_res_list.emplace_back(
          reinterpret_cast<uint8 *>(const_cast<char *>(t_tuple.c_str())));
    }
  }

  // ------------------------------------------------------------------
  // 5. Decrypt local results
  // ------------------------------------------------------------------
  uint8_t K_w[DIGEST_SIZE];
  hmac_digest((unsigned char *)sterm.c_str(), sterm.size(), K, SM4_BLOCK_SIZE,
              K_w);

  for (auto encrypted_res : encrypted_res_list) {
    int ind;
    sm4_decrypt(encrypted_res + SM4_BLOCK_SIZE, sizeof(int), K_w, encrypted_res,
                reinterpret_cast<uint8_t *>(&ind));
    res.push_back(ind);
  }

  return res;
}
