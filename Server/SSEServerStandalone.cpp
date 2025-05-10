#include "Core/SSEServerHandler.h"
#include "GGM/GGMNode.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <chrono>
#include <cstring>
#include <execution>
#include <format>
#include <iostream>
#include <map>
#include <memory>
#include <msgpack.hpp>
#include <mutex>
#include <shared_mutex>
#include <string_view>
#include <thread>
#include <type_traits>
#include <unordered_map>
#include <vector>

#include "Util/CommonUtil.h"

static constexpr uint16_t DEFAULT_PORT = 5000;

// Helper: get current timestamp in human-readable form with millisecond
// resolution
static std::string current_timestamp() {
  using namespace std::chrono;
  auto now = system_clock::now();
  auto ms = duration_cast<milliseconds>(now.time_since_epoch()) % 1000;
  return std::format("{:%F %T}.{:03d}", now, ms.count());
}

// Simple logger using std::format (C++20). Marked constexpr so it can appear in
// constant-evaluated contexts; guarded with std::is_constant_evaluated to avoid
// performing I/O during compile-time evaluation.
template <typename... Args>
constexpr void log(std::format_string<Args...> fmt, Args &&...args) {
  if (!std::is_constant_evaluated()) {
    std::cout << std::format("[{}] ", current_timestamp())
              << std::format(fmt, std::forward<Args>(args)...) << std::endl;
  }
}

// +++ NEW HELPER: pretty-print a duration with adaptive time units +++
// Returns a human-readable string such as "123 µs", "4.23 s", "1.87 h", ...
static std::string format_duration(std::chrono::steady_clock::duration dur) {
  using namespace std::chrono;
  if (dur < microseconds{1}) {
    return std::format("{} ns", duration_cast<nanoseconds>(dur).count());
  } else if (dur < milliseconds{1}) {
    return std::format("{} us", duration_cast<microseconds>(dur).count());
  } else if (dur < seconds{1}) {
    return std::format("{} ms", duration_cast<milliseconds>(dur).count());
  } else if (dur < minutes{1}) {
    return std::format("{:.3f} s", duration<double>(dur).count());
  } else if (dur < hours{1}) {
    return std::format("{:.3f} min", duration<double, std::ratio<60>>(dur).count());
  } else {
    return std::format("{:.3f} h", duration<double, std::ratio<3600>>(dur).count());
  }
}

// Utility function: read exactly len bytes from fd.
static bool read_full(int fd, void *buf, size_t len) {
  uint8_t *ptr = static_cast<uint8_t *>(buf);
  size_t read_bytes = 0;
  while (read_bytes < len) {
    ssize_t n = ::read(fd, ptr + read_bytes, len - read_bytes);
    if (n <= 0) {
      return false;
    }
    read_bytes += static_cast<size_t>(n);
  }
  return true;
}

// Utility function: write exactly len bytes to fd.
static bool write_full(int fd, const void *buf, size_t len) {
  const uint8_t *ptr = static_cast<const uint8_t *>(buf);
  size_t written = 0;
  while (written < len) {
    ssize_t n = ::write(fd, ptr + written, len - written);
    if (n <= 0) {
      return false;
    }
    written += static_cast<size_t>(n);
  }
  return true;
}

// Send a msgpack serialised buffer with length-prefix framing (uint32
// big-endian)
static bool send_msg(int fd, const msgpack::sbuffer &buf) {
  uint32_t net_len = htonl(static_cast<uint32_t>(buf.size()));
  if (!write_full(fd, &net_len, sizeof(net_len)))
    return false;
  return write_full(fd, buf.data(), buf.size());
}

// +++ Added to support multiple handler instances (e.g. TEDB/XEDB) +++
// Each logical database is identified by a string key ("tedb", "xedb", ...)
// and is protected by its own shared_mutex for concurrent access.
struct HandlerContext {
  std::shared_ptr<SSEServerHandler> handler;
  std::shared_ptr<std::shared_mutex> mtx;
  HandlerContext()
      : handler(nullptr), mtx(std::make_shared<std::shared_mutex>()) {}
};

static std::unordered_map<std::string, HandlerContext>
    g_handlers;                       // db_id -> context
static std::mutex g_handlers_map_mtx; // guards g_handlers modifications
// -------------------------------------------------------------------

// Convenience helpers to reduce repetition inside the request loop
static void send_error(int client_fd, const std::string &msg) {
  msgpack::sbuffer sbuf;
  msgpack::pack(sbuf, std::map<std::string, std::string>{{"error", msg}});
  send_msg(client_fd, sbuf);
}

static void send_status_ok(int client_fd) {
  msgpack::sbuffer sbuf;
  msgpack::pack(sbuf, std::map<std::string, std::string>{{"status", "ok"}});
  send_msg(client_fd, sbuf);
}

static bool
check_handler_ready(const std::shared_ptr<SSEServerHandler> &handler,
                    int client_fd) {
  if (!handler) {
    send_error(client_fd, "handler not initialised");
    return false;
  }
  return true;
}

// Handle a single connected client. Runs in its own thread.
static void handle_client(int client_fd) {
  while (true) {
    uint32_t net_len;
    if (!read_full(client_fd, &net_len, sizeof(net_len)))
      break;
    uint32_t len = ntohl(net_len);
    std::vector<char> data(len);
    if (!read_full(client_fd, data.data(), len))
      break;

    try {
      msgpack::object_handle oh = msgpack::unpack(data.data(), data.size());
      msgpack::object obj = oh.get();
      std::map<std::string, msgpack::object> req;
      obj.convert(req);
      std::string cmd_str;
      req["cmd"].convert(cmd_str);
      enum class CommandType {
        AddEntries,
        Search,
        InitHandler,
        BatchAddEntries,
        Unknown
      };
      // Determine the logical database this request targets. Defaults to
      // "default".
      std::string db_id = "default";
      auto db_field_it = req.find("db");
      if (db_field_it != req.end()) {
        try {
          db_field_it->second.convert(db_id);
        } catch (...) {
          // ignore malformed db field, fall back to default
        }
      }

      // Pointers to the actual handler & its mutex (if any)
      std::shared_ptr<SSEServerHandler> handler_ptr;
      std::shared_ptr<std::shared_mutex> handler_mtx;
      {
        std::lock_guard<std::mutex> map_lock(g_handlers_map_mtx);
        auto it_ctx = g_handlers.find(db_id);
        if (it_ctx != g_handlers.end()) {
          handler_ptr = it_ctx->second.handler;
          handler_mtx = it_ctx->second.mtx;
        }
      }
      static const std::unordered_map<std::string_view, CommandType> kCmdMap{
          {"add_entries", CommandType::AddEntries},
          {"add_entries_batch", CommandType::BatchAddEntries},
          {"search", CommandType::Search},
          {"init_handler", CommandType::InitHandler}};
      CommandType cmd = CommandType::Unknown;
      auto it = kCmdMap.find(cmd_str);
      if (it != kCmdMap.end())
        cmd = it->second;

      switch (cmd) {
      case CommandType::AddEntries: {
        if (!check_handler_ready(handler_ptr, client_fd)) {
          break;
        }
        std::unique_lock<std::shared_mutex> lock(*handler_mtx);
        auto start = std::chrono::steady_clock::now();
        std::string label, tag;
        std::vector<std::string> ciphertext_list;
        req["label"].convert(label);
        req["tag"].convert(tag);
        req["ciphertext_list"].convert(ciphertext_list);
        handler_ptr->add_entries(label, tag, std::move(ciphertext_list));
        auto dur = std::chrono::steady_clock::now() - start;
        log("add_entries took {}", format_duration(dur));
        // send simple ack
        send_status_ok(client_fd);
        break;
      }
      case CommandType::BatchAddEntries: {
        if (!check_handler_ready(handler_ptr, client_fd)) {
          break;
        }
        // entries is vector of tuple<string,label>,string tag, vector<string>
        // ciphertext_list
        std::vector<
            std::tuple<std::string, std::string, std::vector<std::string>>>
            entries;
        try {
          req["entries"].convert(entries);
        } catch (...) {
          send_error(client_fd, "invalid entries");
          break;
        }
        auto start = std::chrono::steady_clock::now();
        {
          std::unique_lock<std::shared_mutex> lock(*handler_mtx);
          std::for_each(std::execution::unseq, entries.begin(), entries.end(),
                        [&](const auto &one) {
                          const auto &label = std::get<0>(one);
                          const auto &tag = std::get<1>(one);
                          const auto &cipher_list = std::get<2>(one);
                          handler_ptr->add_entries(label, tag, cipher_list);
                        });
        }
        auto dur = std::chrono::steady_clock::now() - start;
        log("add_entries_batch ({} items) took {}", entries.size(), format_duration(dur));
        send_status_ok(client_fd);
        break;
      }
      case CommandType::Search: {
        if (!check_handler_ready(handler_ptr, client_fd)) {
          break;
        }
        std::shared_lock<std::shared_mutex> read_lock(*handler_mtx);
        auto start = std::chrono::steady_clock::now();
        std::string token_str;
        std::vector<GGMNode> node_list;
        int level;
        req["token"].convert(token_str);
        req["node_list"].convert(node_list);
        req["level"].convert(level);
        if (token_str.size() != DIGEST_SIZE) {
          std::cerr << "Invalid token size from client." << std::endl;
          break;
        }
        std::vector<std::string> res =
            handler_ptr->search((uint8_t *)token_str.data(), node_list, level);
        auto dur = std::chrono::steady_clock::now() - start;
        log("search took {}", format_duration(dur));
        {
          msgpack::sbuffer sbuf;
          msgpack::pack(sbuf, res);
          send_msg(client_fd, sbuf);
        }
        break;
      }
      case CommandType::InitHandler: {
        int new_size = 0;
        try {
          req["ggm_size"].convert(new_size);
        } catch (...) {
          msgpack::sbuffer sbuf;
          msgpack::pack(sbuf, std::map<std::string, std::string>{
                                  {"error", "missing ggm_size"}});
          send_msg(client_fd, sbuf);
          break;
        }
        if (new_size <= 0) {
          msgpack::sbuffer sbuf;
          msgpack::pack(sbuf, std::map<std::string, std::string>{
                                  {"error", "invalid ggm_size"}});
          send_msg(client_fd, sbuf);
          break;
        }

        {
          // Obtain (or create) the context for this db
          HandlerContext *ctx_ptr = nullptr;
          {
            std::lock_guard<std::mutex> map_lock(g_handlers_map_mtx);
            ctx_ptr = &g_handlers[db_id];
            if (!ctx_ptr->mtx) {
              ctx_ptr->mtx = std::make_shared<std::shared_mutex>();
            }
          }
          std::unique_lock<std::shared_mutex> lock(*ctx_ptr->mtx);
          ctx_ptr->handler = std::make_shared<SSEServerHandler>(new_size);
        }
        log("[db:{}] Handler (re)initialised with GGM_SIZE {}", db_id,
            new_size);
        send_status_ok(client_fd);
        break;
      }
      case CommandType::Unknown:
      default: {
        // unknown command
        send_error(client_fd, "unknown cmd");
        break;
      }
      }
    } catch (const std::exception &e) {
      std::cerr << "Error processing request: " << e.what() << std::endl;
      break;
    }
  }
  close(client_fd);
}

int main(int argc, char *argv[]) {
  if (argc > 1) {
    std::cerr << "Usage: " << argv[0] << std::endl;
    return 1;
  }

  int server_fd = ::socket(AF_INET, SOCK_STREAM, 0);
  if (server_fd < 0) {
    perror("socket");
    return 1;
  }
  int opt = 1;
  setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = INADDR_ANY;
  addr.sin_port = htons(DEFAULT_PORT);

  if (bind(server_fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) < 0) {
    perror("bind");
    close(server_fd);
    return 1;
  }

  if (listen(server_fd, 16) < 0) {
    perror("listen");
    close(server_fd);
    return 1;
  }
  log("SSE Server listening on port {}", DEFAULT_PORT);

  while (true) {
    sockaddr_in client_addr{};
    socklen_t client_len = sizeof(client_addr);
    int client_fd = accept(
        server_fd, reinterpret_cast<sockaddr *>(&client_addr), &client_len);
    if (client_fd < 0) {
      perror("accept");
      continue;
    }
    log("Incoming connection from {}:{}",
        std::string_view(inet_ntoa(client_addr.sin_addr)),
        ntohs(client_addr.sin_port));
    std::thread(handle_client, client_fd).detach();
  }
  close(server_fd);
  return 0;
}
