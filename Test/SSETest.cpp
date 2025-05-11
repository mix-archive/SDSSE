#include "Core/SSEClientHandler.h"
#include <iostream>
#include <vector>

int main() {
  SSEClientHandler client(200, 10, "test", false);

  //    cout <<
  //    duration_cast<microseconds>(system_clock::now().time_since_epoch()).count()
  //    << endl;
  for (int i = 0; i < 200; ++i) {
    client.update(UpdateOP::INS, "test", i, (uint8_t *)&i, sizeof(i));
  }
  //    cout <<
  //    duration_cast<microseconds>(system_clock::now().time_since_epoch()).count()
  //    << endl;
  for (int i = 0; i < 10; ++i) {
    client.update(UpdateOP::DEL, "test", i, (uint8_t *)&i, sizeof(i));
  }

  std::vector<std::string> results = client.search("test");
  for (const std::string &res : results) {
    std::cout << *((int *)res.c_str()) << std::endl;
  }
  return 0;
}