#include "Core/VSDSSECQClient.h"

int main() {
    VSDSSECQClient client;

//    cout << duration_cast<microseconds>(system_clock::now().time_since_epoch()).count() << endl;
    for (int i = 0; i < 10; ++i) {
        client.update(INS, "alice", i);
        client.update(INS, "bob", i);
    }
//    cout << duration_cast<microseconds>(system_clock::now().time_since_epoch()).count() << endl;
    for (int i = 0; i < 3; ++i) {
        client.update(DEL, "bob", i);
    }

    vector<int> results = client.search(2, "alice", "bob");
    for (int res : results) {
        cout << res << endl;
    }
    return 0;
}
