#include "Core/SDSSECQSClient.h"
#include <args.hxx>
#include <cstddef>
#include <format>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

static inline std::vector<std::pair<unsigned int, std::vector<std::string>>>
parse_file(const std::string &filename) {
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
      std::cerr << std::format("Invalid line (missing id): {}", line)
                << std::endl;
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

static void index_file(const std::string &filename) {
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

static void delete_id(const std::string &filename, unsigned int target_id) {
  auto data = parse_file(filename);
  SDSSECQSClient client(static_cast<int>(data.size()),
                        static_cast<int>(data.size()), false);

  auto it =
      std::find_if(data.begin(), data.end(), [target_id](const auto &pair) {
        return pair.first == target_id;
      });
  if (it == data.end()) {
    std::cout << std::format("No entry with id {} found in file.", target_id)
              << std::endl;
    return;
  }
  const auto &[id, keywords] = *it;
  for (const auto &keyword : keywords) {
    client.update(DEL, keyword, id);
  }
  // flush deletions
  client.flush();
  std::cout << std::format("Deletion done for id {}, {} keywords affected",
                           target_id, keywords.size())
            << std::endl;
}

static void search_keywords(const std::string &filename,
                            const std::vector<std::string> &search_keywords) {
  if (search_keywords.empty()) {
    std::cerr << "At least one keyword is required for search." << std::endl;
    return;
  }

  // Load data to reconstruct keyword counters (CT) so token generation works.
  auto data = parse_file(filename);
  SDSSECQSClient client(static_cast<int>(data.size()),
                        static_cast<int>(data.size()), false);

  std::unordered_map<std::string, int> counts;
  std::unordered_map<unsigned int, std::vector<std::string>> id_to_keywords;
  for (const auto &[id, keywords] : data) {
    for (const auto &kw : keywords) {
      counts[kw] += 1;
    }
    id_to_keywords[id] = keywords;
  }
  std::cout << std::format("{} keywords found in file.", counts.size())
            << std::endl;
  client.load_CT(counts);

  // direct call with new signature
  std::vector<int> result = client.search(search_keywords);

  // ------------------- output processing -------------------
  if (result.empty()) {
    std::cout << "No match found." << std::endl;
    return;
  }

  const std::string red_start = "\033[1;31m"; // bold red
  const std::string color_end = "\033[0m";
  for (const auto &id : result) {
    const auto &keywords = id_to_keywords[id];
    std::string line;
    for (const auto &kw : keywords) {
      if (std::find(search_keywords.begin(), search_keywords.end(), kw) !=
          search_keywords.end()) {
        line += red_start + kw + color_end;
      } else {
        line += kw;
      }
      line += " ";
    }
    std::cout << std::format("{}:\t{}", id, line) << std::endl;
  }
}

int main(int argc, char **argv) {
  args::ArgumentParser parser("Searchable encryption for conjunctive queries");

  args::Group subcommands(parser, "subcommands");
  args::Command index(subcommands, "index", "index the file");
  args::Command delete_(subcommands, "delete", "delete the file");
  args::Command search(subcommands, "search", "search the file");
  args::HelpFlag help(parser, "help", "Display this help menu", {'h', "help"});
  args::ArgumentParser subparser("index");
  args::Positional<std::string> file(index, "file", "The file to index");
  args::Positional<std::string> file_del(delete_, "file",
                                         "The file to delete from");
  args::Positional<unsigned int> id(delete_, "id", "The id to delete");
  args::Positional<std::string> file_search(search, "file",
                                            "The file to search in");
  args::PositionalList<std::string> keywords(search, "keywords",
                                             "The keywords to search for");

  try {
    parser.ParseCLI(argc, argv);
  } catch (args::Help) {
    std::cout << parser;
    return 0;
  } catch (args::ParseError e) {
    std::cerr << e.what() << std::endl;
    std::cerr << parser;
    return 1;
  } catch (args::ValidationError e) {
    std::cerr << e.what() << std::endl;
    std::cerr << parser;
    return 1;
  }

  if (index) {
    index_file(args::get(file));
  } else if (delete_) {
    if (!file_del || !id) {
      std::cerr << "Both file and id are required for delete operation"
                << std::endl;
      std::cerr << parser;
      return 1;
    }
    delete_id(args::get(file_del), args::get(id));
  } else if (search) {
    if (!file_search || !keywords) {
      std::cerr << "Both file and keywords are required for search operation"
                << std::endl;
      std::cerr << parser;
      return 1;
    }
    search_keywords(args::get(file_search), args::get(keywords));
  } else {
    std::cerr << "No command specified" << std::endl;
    std::cerr << parser;
    return 1;
  }
}