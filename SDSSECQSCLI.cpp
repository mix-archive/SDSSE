// SDSSECQSCLI.cpp
#include "Core/SDSSECQSClient.h"
#include <cstddef>
#include <format>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

using std::cerr;
using std::cout;
using std::endl;
using std::string;
using std::vector;

static void print_usage(const char *prog_name) {
  cout << "Usage:" << endl;
  cout << "  " << prog_name << " index  <file>" << endl;
  cout << "  " << prog_name << " delete <file> <id>" << endl;
  cout << "  " << prog_name << " search <file> <keyword1> [keyword2 ...]"
       << endl;
}

static inline std::vector<std::pair<unsigned int, std::vector<std::string>>>
parse_file(const string &filename) {
  std::ifstream fin(filename);
  if (!fin.is_open()) {
    throw std::runtime_error("Cannot open file: " + filename);
  }
  std::vector<std::pair<unsigned int, std::vector<std::string>>> data;
  std::string line;
  while (std::getline(fin, line)) {
    if (line.empty())
      continue;
    std::stringstream ss(line);
    unsigned int id;
    if (!(ss >> id)) {
      cerr << std::format("Invalid line (missing id): {}", line) << endl;
      continue;
    }
    std::vector<std::string> keywords;
    std::string keyword;
    while (ss >> keyword) {
      keywords.emplace_back(std::move(keyword));
    }
    data.emplace_back(id, std::move(keywords));
  }
  return data;
}

static void index_file(const string &filename) {
  auto data = parse_file(filename);
  SDSSECQSClient client(static_cast<int>(data.size()),
                        static_cast<int>(data.size()), true);
  size_t total_keywords = 0;
  for (size_t i = 0; i < data.size(); ++i) {
    const auto &[id, keywords] = data[i];
    for (const auto &keyword : keywords) {
      client.update(INS, keyword, id);
    }
    if (i % 1000 == 0) {
      std::cout << std::format("Indexed {}/{} lines, {} keywords", i,
                               data.size(), total_keywords)
                << std::endl;
    }
    total_keywords += keywords.size();
  }
  std::cout << std::format("Index finished, total {} lines, {} keywords",
                           data.size(), total_keywords)
            << std::endl;
  client.flush();
}

static void delete_id(const string &filename, unsigned int target_id) {
  auto data = parse_file(filename);
  SDSSECQSClient client(static_cast<int>(data.size()),
                        static_cast<int>(data.size()), false);

  auto it =
      std::find_if(data.begin(), data.end(), [target_id](const auto &pair) {
        return pair.first == target_id;
      });
  if (it == data.end()) {
    cout << std::format("No entry with id {} found in file.", target_id)
         << endl;
    return;
  }
  const auto &[id, keywords] = *it;
  for (const auto &keyword : keywords) {
    client.update(DEL, keyword, id);
  }
  // flush deletions
  client.flush();
  cout << std::format("Deletion done for id {}, {} keywords affected",
                      target_id, keywords.size())
       << endl;
}

static void search_keywords(const string &filename,
                            const vector<string> &search_keywords) {
  if (search_keywords.empty()) {
    cerr << "At least one keyword is required for search." << endl;
    return;
  }

  // Load data to reconstruct keyword counters (CT) so token generation works.
  auto data = parse_file(filename);
  SDSSECQSClient client(static_cast<int>(data.size()),
                        static_cast<int>(data.size()), false);

  std::unordered_map<string, int> counts;
  for (const auto &[id, keywords] : data) {
    for (const auto &kw : keywords) {
      counts[kw] += 1;
    }
  }
  cout << std::format("{} keywords found in file.", counts.size()) << endl;
  client.load_CT(counts);

  // direct call with new signature
  vector<int> result = client.search(search_keywords);

  // ------------------- output processing -------------------
  if (result.empty()) {
    cout << "No match found." << endl;
    return;
  }

  // Build map from id to line for quick lookup.
  std::ifstream fin2(filename);
  if (!fin2.is_open()) {
    cerr << "Cannot open file: " << filename << endl;
    return;
  }
  std::unordered_map<int, string> id_to_line;
  string line2;
  while (std::getline(fin2, line2)) {
    if (line2.empty())
      continue;
    std::stringstream ss(line2);
    int idtmp;
    if (!(ss >> idtmp))
      continue;
    id_to_line[idtmp] = line2;
  }

  const string red_start = "\033[1;31m"; // bold red
  const string color_end = "\033[0m";

  for (int id : result) {
    cout << id << "\t";
    auto it = id_to_line.find(id);
    if (it == id_to_line.end()) {
      cout << "<line not found in file>" << endl;
      continue;
    }
    string l = it->second;
    // highlight each keyword
    for (const auto &kw : search_keywords) {
      size_t pos = 0;
      while ((pos = l.find(kw, pos)) != string::npos) {
        l.replace(pos, kw.size(), red_start + kw + color_end);
        pos += red_start.size() + kw.size() + color_end.size();
      }
    }
    cout << l << endl;
  }
}

int main(int argc, char *argv[]) {
  if (argc < 2) {
    print_usage(argv[0]);
    return 1;
  }
  string command = argv[1];
  if (command == "index") {
    if (argc != 3) {
      print_usage(argv[0]);
      return 1;
    }
    index_file(argv[2]);
  } else if (command == "delete") {
    if (argc != 4) {
      print_usage(argv[0]);
      return 1;
    }
    int id = std::stoi(argv[3]);
    delete_id(argv[2], id);
  } else if (command == "search") {
    if (argc < 4) {
      print_usage(argv[0]);
      return 1;
    }
    string filename = argv[2];
    vector<string> keywords;
    for (int i = 3; i < argc; ++i) {
      keywords.emplace_back(argv[i]);
    }
    search_keywords(filename, keywords);
  } else {
    print_usage(argv[0]);
    return 1;
  }
  return 0;
}