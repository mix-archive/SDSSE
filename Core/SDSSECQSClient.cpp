#include "SDSSECQSClient.h"
#include <pbc/pbc.h>

using PBC::Zr, PBC::GT, PBC::GPP, PBC::Pairing;
using std::vector, std::string;

Zr SDSSECQSClient::Fp(uint8_t *input, size_t input_size, uint8_t *key) {
  uint8_t PRF[DIGEST_SIZE];
  hmac_digest(input, input_size, key, SM4_BLOCK_SIZE, PRF);

  return Zr(*e, (void *)PRF, DIGEST_SIZE);
}

SDSSECQSClient::SDSSECQSClient(int ins_size, int del_size, bool init_remote)
    : TEDB(ins_size, del_size, "tedb", init_remote),
      XEDB(ins_size, del_size, "xedb", init_remote) {
  // generate or load pairing parameters. If pairing.param does not exist,
  // generate default Type A parameters (rbits=160, qbits=512).
  FILE *sysParamFile = fopen("pairing.param", "r");
  if (!sysParamFile) {
    // Create new param file
    FILE *paramOut = fopen("pairing.param", "w");
    if (!paramOut) {
      fprintf(stderr, "[SDSSECQSClient] Cannot create pairing.param file.\n");
      throw std::runtime_error("failed to create pairing.param");
    }
    // Use libpbc to generate Type A parameters. 160-bit r, 512-bit q.
    pbc_param_t p;
    pbc_param_init_a_gen(p, 160, 512);
    pbc_param_out_str(paramOut, p);
    pbc_param_clear(p);
    fclose(paramOut);
    // reopen for reading
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

void SDSSECQSClient::update(UpdateOP op, const string &keyword, int ind) {
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
  memcpy(eyc.data() + sizeof(encrypted_id) + y_in_byte.size(), &c, sizeof(int));
  // upload to TEDB
  TEDB.update(op, keyword, ind, eyc.data(), eyc.size());

  // generate xterm=g^(Fp(K_X, w)*xind)
  GT wxtag = (*gpp) ^ (Fp((uint8_t *)keyword.c_str(), keyword.size(), K_X) *
                       xind / Fp((uint8_t *)Z_w.data(), Z_w.size(), K_x));
  vector<uint8_t> wxtag_in_byte(
      element_length_in_bytes(const_cast<element_s *>(wxtag.getElement())) +
      sizeof(int));
  element_to_bytes(wxtag_in_byte.data(),
                   const_cast<element_s *>(wxtag.getElement()));
  memcpy(wxtag_in_byte.data() + element_length_in_bytes(const_cast<element_s *>(
                                    wxtag.getElement())),
         &c, sizeof(int));
  // upload to XEDB
  XEDB.update(op, keyword, ind, wxtag_in_byte.data(), wxtag_in_byte.size());
}

std::vector<int>
SDSSECQSClient::search(const std::vector<std::string> &keywords) {
  std::vector<int> res;

  if (keywords.empty()) {
    return res;
  }

  const std::string &sterm = keywords[0];
  if (CT.find(sterm) == CT.end()) {
    return res;
  }

  // Split conjunctive terms
  std::vector<std::string> xterms;
  if (keywords.size() > 1) {
    xterms.assign(keywords.begin() + 1, keywords.end());
  }

  // ------------------------------------------------------------------
  // 1. Pre-compute tokens
  // ------------------------------------------------------------------
  std::vector<std::vector<GT>> wxtoken_list; // wxtokens for (w,i)
  std::vector<std::vector<Zr>> zxtoken_list; // zx tokens for (x,k)

  if (!xterms.empty()) {
    // wxtokens
    for (int i = 0; i <= CT[sterm]; ++i) {
      std::vector<uint8_t> w_i(sterm.size() + sizeof(int));
      memset(w_i.data(), 0, w_i.size());
      memcpy(w_i.data(), sterm.c_str(), sterm.size());
      memcpy(w_i.data() + sterm.size(), &i, sizeof(int));

      Zr z = Fp(w_i.data(), w_i.size(), K_Z);

      std::vector<GT> token_i(xterms.size());
      for (size_t j = 0; j < xterms.size(); ++j) {
        auto &xterm = xterms[j];
        token_i[j] =
            (*gpp) ^ (z * Fp((uint8_t *)xterm.c_str(), xterm.size(), K_X) *
                      Fp((uint8_t *)sterm.c_str(), sterm.size(), K_z));
      }
      wxtoken_list.emplace_back(std::move(token_i));
    }

    // zxtokens
    for (auto &xterm : xterms) {
      if (CT.find(xterm) == CT.end()) {
        return res;
      }

      std::vector<Zr> zx_i(static_cast<size_t>(CT[xterm] + 1));
      for (size_t k = 0; k < zx_i.size(); ++k) {
        std::vector<uint8_t> w_j(xterm.size() + sizeof(int));
        memset(w_j.data(), 0, w_j.size());
        memcpy(w_j.data(), xterm.c_str(), xterm.size());
        memcpy(w_j.data() + xterm.size(), &k, sizeof(int));
        zx_i[k] = Fp(w_j.data(), w_j.size(), K_x) *
                  Fp((uint8_t *)sterm.c_str(), sterm.size(), K_z);
      }
      zxtoken_list.emplace_back(std::move(zx_i));
    }
  }

  // ------------------------------------------------------------------
  // 2. Query TEDB
  // ------------------------------------------------------------------
  std::vector<std::string> Res_T = TEDB.search(sterm);
  if (Res_T.empty()) {
    return res;
  }

  // ------------------------------------------------------------------
  // 3. Query XEDB
  // ------------------------------------------------------------------
  int XSET_SIZE = get_BF_size(XSET_HASH, MAX_DB_SIZE, XSET_FP);
  BloomFilter<128, XSET_HASH> Res_WX(XSET_SIZE);
  for (size_t j = 0; j < xterms.size(); ++j) {
    std::vector<std::string> Res_wxtags = XEDB.search(xterms[j]);
    if (Res_wxtags.empty()) {
      return res;
    }
    for (const auto &wxtag_string : Res_wxtags) {
      GT tag =
          GT(*e, reinterpret_cast<const unsigned char *>(wxtag_string.c_str()),
             128) ^
          zxtoken_list[j][*reinterpret_cast<const int *>(wxtag_string.c_str() +
                                                         128)];
      Res_WX.add_tag((uint8_t *)tag.toString().c_str());
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
      GT tag = wxtoken_list[*reinterpret_cast<const int *>(
                   t_tuple.c_str() + SM4_BLOCK_SIZE + sizeof(int) + 20)][j] ^
               y;
      if (!Res_WX.might_contain((uint8_t *)tag.toString().c_str())) {
        flag = false;
        break;
      }
    }
    if (flag) {
      encrypted_res_list.emplace_back((uint8 *)t_tuple.c_str());
    }
  }

  // ------------------------------------------------------------------
  // 5. Decrypt results locally
  // ------------------------------------------------------------------
  uint8_t K_w[DIGEST_SIZE];
  hmac_digest((unsigned char *)sterm.c_str(), sterm.size(), K, SM4_BLOCK_SIZE,
              K_w);

  for (auto encrypted_res : encrypted_res_list) {
    int ind;
    sm4_decrypt(encrypted_res + SM4_BLOCK_SIZE, sizeof(int), K_w, encrypted_res,
                (uint8_t *)&ind);
    res.push_back(ind);
  }

  return res;
}
