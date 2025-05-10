// SDSSECQSCLI.cpp
#include "Core/SDSSECQSClient.h"
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

static size_t count_lines(std::ifstream &ifs) {
  size_t lines = 0;
  string tmp;
  while (std::getline(ifs, tmp)) {
    ++lines;
  }
  ifs.clear();
  ifs.seekg(0);
  return lines;
}

static void index_file(const string &filename) {
  std::ifstream fin(filename);
  if (!fin.is_open()) {
    cerr << "Cannot open file: " << filename << endl;
    return;
  }
  size_t total = count_lines(fin);
  // Build client with room for all inserts; allow deletions up to same size.
  SDSSECQSClient client(static_cast<int>(total), static_cast<int>(total), true);

  string line;
  while (std::getline(fin, line)) {
    if (line.empty())
      continue;
    std::stringstream ss(line);
    int id;
    if (!(ss >> id)) {
      cerr << "Invalid line (missing id): " << line << endl;
      continue;
    }
    string keyword;
    while (ss >> keyword) {
      client.update(INS, keyword, id);
    }
  }
  // Commit batched inserts
  client.flush();
  cout << "Indexing finished for " << total << " rows." << endl;
}

static void delete_id(const string &filename, int target_id) {
  std::ifstream fin(filename);
  if (!fin.is_open()) {
    cerr << "Cannot open file: " << filename << endl;
    return;
  }
  size_t total = count_lines(fin);
  SDSSECQSClient client(static_cast<int>(total), static_cast<int>(total));

  string line;
  bool found = false;
  while (std::getline(fin, line)) {
    if (line.empty())
      continue;
    std::stringstream ss(line);
    int id;
    if (!(ss >> id)) {
      continue;
    }
    if (id != target_id)
      continue;
    found = true;
    string keyword;
    while (ss >> keyword) {
      client.update(DEL, keyword, id);
    }
  }
  // flush deletions
  client.flush();
  if (found) {
    cout << "Deletion done for id " << target_id << endl;
  } else {
    cout << "No entry with id " << target_id << " found in file." << endl;
  }
}

static void search_keywords(const string &filename,
                            const vector<string> &keywords) {
  if (keywords.empty()) {
    cerr << "At least one keyword is required for search." << endl;
    return;
  }
  // Reconstruct keyword counters (CT) by scanning the dataset so that tokens
  // can be generated correctly.
  std::ifstream fin(filename);
  if (!fin.is_open()) {
    cerr << "Cannot open file: " << filename << endl;
    return;
  }
  std::unordered_map<string, int> counts;
  size_t total = 0;
  string line;
  while (std::getline(fin, line)) {
    if (line.empty())
      continue;
    std::stringstream ss(line);
    int id;
    if (!(ss >> id))
      continue;
    string kw;
    while (ss >> kw) {
      counts[kw] += 1;
    }
    ++total;
  }
  // convert to CT format (count - 1)
  for (auto &pair : counts) {
    pair.second = pair.second - 1;
  }

  SDSSECQSClient client(static_cast<int>(total), static_cast<int>(total),
                        false);
  client.load_CT(counts);

  vector<int> result;
  switch (keywords.size()) {
  case 1:
    result = client.search(1, keywords[0].c_str());
    break;
  case 2:
    result = client.search(2, keywords[0].c_str(), keywords[1].c_str());
    break;
  case 3:
    result = client.search(3, keywords[0].c_str(), keywords[1].c_str(),
                           keywords[2].c_str());
    break;
  case 4:
    result = client.search(4, keywords[0].c_str(), keywords[1].c_str(),
                           keywords[2].c_str(), keywords[3].c_str());
    break;
  case 5:
    result = client.search(5, keywords[0].c_str(), keywords[1].c_str(),
                           keywords[2].c_str(), keywords[3].c_str(),
                           keywords[4].c_str());
    break;
  default:
    cerr << "Search with up to 5 keywords supported." << endl;
    return;
  }

  if (result.empty()) {
    cout << "No match found." << endl;
  } else {
    // Build map from id to line for quick lookup
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
      for (const auto &kw : keywords) {
        size_t pos = 0;
        while ((pos = l.find(kw, pos)) != string::npos) {
          l.replace(pos, kw.size(), red_start + kw + color_end);
          pos += red_start.size() + kw.size() + color_end.size();
        }
      }
      cout << l << endl;
    }
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