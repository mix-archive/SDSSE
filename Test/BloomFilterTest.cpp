#include <iostream>

#include "../BF/BloomFilter.h"


int main() {
    auto BF_size = get_BF_size(20, 3, 0.0000001);

    BloomFilter<1, 20> bf(BF_size);

    uint8_t tag1 = 1;
    uint8_t tag2 = 2;
    uint8_t tag3 = 3;

    // add items into bf
    bf.add_tag(&tag1);
    bf.add_tag(&tag2);

    cout << "tag1:" << bf.might_contain(&tag1) << endl;
    cout << "tag2:" << bf.might_contain(&tag2) << endl;
    cout << "tag3:" << bf.might_contain(&tag3) << endl;

    return 0;
}
