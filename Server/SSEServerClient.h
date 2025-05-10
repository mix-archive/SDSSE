/*
 * Header-only SSE Server Client SDK
 */
#pragma once

#include "GGM/GGMNode.h"
#include "Util/CommonUtil.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstring>
#include <iostream>
#include <msgpack.hpp>
#include <string>
#include <vector>

class SSEServerClient {
public:
  explicit SSEServerClient(std::string host = "127.0.0.1", uint16_t port = 5000,
                           std::string db_id = "default")
      : host_(std::move(host)), port_(port), db_id_(std::move(db_id)), fd_(-1) {
  }

  // Send add_entries command. Returns true on success.
  inline bool
  add_entries(const std::string &label, const std::string &tag,
              const std::vector<std::string> &ciphertext_list) const {
    int fd = ensure_socket();
    if (fd < 0)
      return false;

    msgpack::sbuffer buf;
    msgpack::packer packer(buf);
    packer.pack_map(5);
    packer.pack(std::string("cmd"));
    packer.pack(std::string("add_entries"));
    packer.pack(std::string("db"));
    packer.pack(db_id_);
    packer.pack(std::string("label"));
    packer.pack(label);
    packer.pack(std::string("tag"));
    packer.pack(tag);
    packer.pack(std::string("ciphertext_list"));
    packer.pack(ciphertext_list);

    if (!send_msg(fd, buf)) {
      close_socket();
      return false;
    }
    msgpack::object_handle oh;
    bool ok = recv_msg(fd, oh);
    if (!ok) {
      close_socket();
      return false;
    }
    std::map<std::string, std::string> res;
    oh.get().convert(res);
    return res["status"] == "ok";
  }

  // Search API.
  inline bool search(const std::string &token,
                     const std::vector<GGMNode> &node_list, int level,
                     std::vector<std::string> &res) const {
    if (token.size() != DIGEST_SIZE) {
      std::cerr << "Token size mismatch" << std::endl;
      return false;
    }
    int fd = ensure_socket();
    if (fd < 0)
      return false;

    msgpack::sbuffer buf;
    msgpack::packer packer(buf);
    packer.pack_map(5);
    packer.pack(std::string("cmd"));
    packer.pack(std::string("search"));
    packer.pack(std::string("db"));
    packer.pack(db_id_);
    packer.pack(std::string("token"));
    packer.pack(token);
    packer.pack(std::string("node_list"));
    packer.pack(node_list);
    packer.pack(std::string("level"));
    packer.pack(level);

    if (!send_msg(fd, buf)) {
      close_socket();
      return false;
    }
    msgpack::object_handle oh;
    bool ok = recv_msg(fd, oh);
    if (!ok) {
      close_socket();
      return false;
    }
    oh.get().convert(res);
    return true;
  }

  // Initialise / re-initialise the server-side handler with given GGM size.
  inline bool init_handler(int ggm_size) const {
    if (ggm_size <= 0) {
      std::cerr << "Invalid ggm_size" << std::endl;
      return false;
    }
    int fd = ensure_socket();
    if (fd < 0)
      return false;

    msgpack::sbuffer buf;
    msgpack::packer packer(buf);
    packer.pack_map(3);
    packer.pack(std::string("cmd"));
    packer.pack(std::string("init_handler"));
    packer.pack(std::string("db"));
    packer.pack(db_id_);
    packer.pack(std::string("ggm_size"));
    packer.pack(ggm_size);

    if (!send_msg(fd, buf)) {
      close_socket();
      return false;
    }
    msgpack::object_handle oh;
    bool ok = recv_msg(fd, oh);
    if (!ok) {
      close_socket();
      return false;
    }
    std::map<std::string, std::string> res;
    try {
      oh.get().convert(res);
      return res["status"] == "ok";
    } catch (...) {
      return false;
    }
  }

  // change the target database (e.g. "tedb", "xedb") at runtime
  inline void set_db(const std::string &db) { db_id_ = db; }

  // Explicitly close underlying TCP connection (optional).
  inline void close() const { close_socket(); }

  // Destructor: ensure we clean up socket.
  ~SSEServerClient() { close_socket(); }

  // Send batch add_entries command.
  inline bool add_entries_batch(
      const std::vector<std::tuple<std::string, std::string,
                                   std::vector<std::string>>> &entries) const {
    if (entries.empty())
      return true;
    int fd = ensure_socket();
    if (fd < 0)
      return false;

    msgpack::sbuffer buf;
    msgpack::packer packer(buf);
    packer.pack_map(3);
    packer.pack(std::string("cmd"));
    packer.pack(std::string("add_entries_batch"));
    packer.pack(std::string("db"));
    packer.pack(db_id_);
    packer.pack(std::string("entries"));
    packer.pack(entries);

    if (!send_msg(fd, buf)) {
      close_socket();
      return false;
    }
    msgpack::object_handle oh;
    if (!recv_msg(fd, oh)) {
      close_socket();
      return false;
    }
    std::map<std::string, std::string> res;
    try {
      oh.get().convert(res);
      return res["status"] == "ok";
    } catch (...) {
      return false;
    }
  }

private:
  std::string host_;
  uint16_t port_;
  std::string db_id_;
  mutable int fd_; // persistent socket, -1 means closed

  // Ensure we have an open socket, connect if necessary.
  inline int ensure_socket() const {
    if (fd_ >= 0)
      return fd_;
    fd_ = connect_socket_raw();
    return fd_;
  }

  inline void close_socket() const {
    if (fd_ >= 0) {
      ::close(fd_);
      fd_ = -1;
    }
  }

  // Low-level connect helper (returns fd or -1)
  inline int connect_socket_raw() const {
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
      perror("socket");
      return -1;
    }
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port_);
    if (inet_pton(AF_INET, host_.c_str(), &addr.sin_addr) != 1) {
      std::cerr << "Invalid host IP " << host_ << std::endl;
      ::close(fd);
      return -1;
    }
    if (connect(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) < 0) {
      perror("connect");
      ::close(fd);
      return -1;
    }
    return fd;
  }

  // I/O helpers (internal linkage via inline static).
  static inline bool read_full(int fd, void *buf, size_t len) {
    auto *ptr = static_cast<uint8_t *>(buf);
    size_t read_bytes = 0;
    while (read_bytes < len) {
      ssize_t n = ::read(fd, ptr + read_bytes, len - read_bytes);
      if (n <= 0)
        return false;
      read_bytes += static_cast<size_t>(n);
    }
    return true;
  }

  static inline bool write_full(int fd, const void *buf, size_t len) {
    const auto *ptr = static_cast<const uint8_t *>(buf);
    size_t written = 0;
    while (written < len) {
      ssize_t n = ::write(fd, ptr + written, len - written);
      if (n <= 0)
        return false;
      written += static_cast<size_t>(n);
    }
    return true;
  }

  static inline bool send_msg(int fd, const msgpack::sbuffer &buf) {
    uint32_t net_len = htonl(static_cast<uint32_t>(buf.size()));
    if (!write_full(fd, &net_len, sizeof(net_len)))
      return false;
    return write_full(fd, buf.data(), buf.size());
  }

  static inline bool recv_msg(int fd, msgpack::object_handle &oh) {
    uint32_t net_len;
    if (!read_full(fd, &net_len, sizeof(net_len)))
      return false;
    uint32_t len = ntohl(net_len);
    std::vector<char> data(len);
    if (!read_full(fd, data.data(), len))
      return false;
    try {
      oh = msgpack::unpack(data.data(), data.size());
      return true;
    } catch (const std::exception &e) {
      std::cerr << "msgpack unpack error: " << e.what() << std::endl;
      return false;
    }
  }
};