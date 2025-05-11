#include "Core/SDSSECQSClient.h"
#include <chrono>
#include <iostream>
#include <vector>

using std::cout, std::endl, std::vector;
using std::chrono::duration_cast, std::chrono::microseconds,
    std::chrono::system_clock;

int main(int argc, char *argv[]) {
  if (argc != 4) {
    cout << "Incorrect Arguments" << endl;
    cout << "The program needs to be run with ./SDSSECQ [w1 size] [w2 size] "
            "[Deletion Size]"
         << endl;
    return -1;
  }

  int w1_size = atoi(argv[1]);
  int w2_size = atoi(argv[2]);
  int del_size = atoi(argv[3]);

  SDSSECQSClient client(1, del_size);

  auto start =
      duration_cast<microseconds>(system_clock::now().time_since_epoch())
          .count();
  for (int i = 0; i < w1_size; ++i) {
    client.update(INS, "alice", i);
  }
  for (int i = 0; i < w2_size; ++i) {
    client.update(INS, "bob", i);
  }
  auto end = duration_cast<microseconds>(system_clock::now().time_since_epoch())
                 .count();
  cout << (float)(end - start) / (float)(w1_size + w2_size)
       << " us per insertion" << endl;
  start = duration_cast<microseconds>(system_clock::now().time_since_epoch())
              .count();
  for (int i = 0; i < del_size; ++i) {
    client.update(DEL, "alice", i);
    client.update(DEL, "bob", i);
  }
  end = duration_cast<microseconds>(system_clock::now().time_since_epoch())
            .count();
  cout << (float)(end - start) / 2 / (float)del_size << " us per deletion"
       << endl;
  // search the database
  start = duration_cast<microseconds>(system_clock::now().time_since_epoch())
              .count();
  vector<int> single_results = client.search({"alice"});
  end = duration_cast<microseconds>(system_clock::now().time_since_epoch())
            .count();
  cout << "Single Keyword Search Time: " << (float)(end - start) / 1000 << " ms"
       << endl;
  start = duration_cast<microseconds>(system_clock::now().time_since_epoch())
              .count();
  vector<int> conjunctive_results = client.search({"alice", "bob"});
  end = duration_cast<microseconds>(system_clock::now().time_since_epoch())
            .count();
  cout << "Two-Keyword Conjunctive Search Time: " << (float)(end - start) / 1000
       << " ms" << endl;
  return 0;
}
