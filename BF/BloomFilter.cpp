//
// Created by shangqi on 11/21/24.
//

#include "BloomFilter.h"

int get_BF_size(int hashes, int items, float fp)
{
return ceil(- items * hashes / log(1 - exp(log(fp) / hashes)));
}