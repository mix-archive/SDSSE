#include <chrono>

#include "Core/VSDSSECQClient.h"

using namespace chrono;
int main() {
    VSDSSECQClient client;

    cout << duration_cast<microseconds>(system_clock::now().time_since_epoch()).count() << endl;
    for (int i = 0; i < 1000; ++i) {
        client.update(INS, "alice", i);
        client.update(INS, "bob", i);
    }
    cout << duration_cast<microseconds>(system_clock::now().time_since_epoch()).count() << endl;
    for (int i = 0; i < 1000; ++i) {
        client.update(DEL, "bob", i);
    }
    cout << duration_cast<microseconds>(system_clock::now().time_since_epoch()).count() << endl;
    vector<int> results = client.search(2, "alice", "bob");
    cout << results.size() << endl;
//    for (int res : results) {
//        cout << res << endl;
//    }
    cout << duration_cast<microseconds>(system_clock::now().time_since_epoch()).count() << endl;
    return 0;
}
