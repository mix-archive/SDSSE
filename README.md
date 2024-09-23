# SDSSE

This repository contains the implementation of SDSSE, the Dynamic Searchable Symmetric Encryption (DSSE) schemes (SDSSE-CQ and SDSSE-CQ-S) we proposed in the PETS submission "*Searchable Encryption for Conjunctive Queries with Extended Forward and Backward Privacy*". The proposed scheme aims to enable conjunctive queries over DSSE schemes with Forward/Backward privacy gurantees. Note that this is a proof-of-concept code implementation and does not include an interactive interface. Instead, we provide a guidance on how to set the parameters to run this code towards various input sizes.

## Requirements

* Git
* Ubuntu version >= 16.04
* gcc/g++ version>=-5 (5.4.0 in ubuntu 16.04)
* cmake >= 3.17
* openssl version >= 1.1.0h
* The Pairing-Based Cryptography Library (PBC) version 0.5.14

### Some Notes for the System Requirements

1. The above setting represents the oldest version we tested with our implementation. We cannot guarantee the code will be compatible with any environments that are older than the above environment settings. On the other hand, although the code has been tested in some newer environments, including Ubuntu 20.04 and gcc/g++ 9.0, we still cannot guarantee its correctness on the latest version of above software, especially because some openssl APIs are deprecated.

2. The implementation cannot run with MacOS because the file system (APFS) of MacOS is not case-sensitive. This creates a collision between the PBC C++ Wrapper and the original PBC library, making the building toolkit unable to build the required library correctly. This issue cannot be addressed even if we run a Docker container upon MacOS since it inherits the underlying file system features. To address this issue, the only solution is to re-format your MacOS file system to APFS (case-sensitive), but this will create incompatibility on some native MacOS software. Hence, we do not recommand to running our code with MacOS.

## Building

Download this repository, and run the following commands:

```bash
cd SDSSE-76F6
mkdir build
cd build
# use cmake to build the code
cmake ..
cmake --build . --target [SDSSECQ|SDSSECQS]
```

## Usage
After compiling the project, you can run the following commands to start the test program:
```bash
cd ../Data
../build/[SDSSECQ|SDSSECQS] 
```

If you experience runtime errors, indicating that the libpbc cannot be found in your system, please run the following command to check `LD_LIBRARY_PATH`:
```bash
echo $LD_LIBRARY_PATH
```
to ensure the path `usr/local/lib` is in that enviroment variable. You may need to manually add it in if there is no such path inside and meet the corresponding runtime error.

## Parameters
As mentioned, the current implementation is a proof-of-concept prototype.To evaluate the proposed protocol, we also implement two test programs to generate synthesis datasets and run our proposed DSSE protocol over them.

### Dataset Size
The source code of those test programs can be found in the root path of the project, namely `SDSSECQ.cpp` and `SDSSECQS.cpp`. The code in this repository inserts 1000 files with two keywords "Alice" and "Bob", deletes 100 files (10% deletion), and then executes the conjunctive query ("Alice" AND "Bob"). To enlarge the size of dataset, one can modify the above two files by increasing the numbers of insertions/deletions or adding more keywords. 

Besides, as the number of keyword-id pairs increases, we should use a larger Bloom filter to keep the XSet for conjunctive queries. Hence, the `XSET_SIZE` and `XSET_HASH` in `Util
/CommonUtil.h` should be updated accordingly. Note that the current parameters `XSET_SIZE=2875518` and `XSET_HASH=20` can support conjunctive queries against a dataset with 100k keyword-id pairs with less than 10^-7 false positive rate. We would refer our readers to [here](https://hur.st/bloomfilter/) to compute the new Bloom filter parameters as required.

### Deletion
Since the deletion is also based on Bloom filter, there are another two Bloom filter parameters, i.e., `GGM_SIZE` and `HASH_SIZE` to be set with the increasing number of deletion operations. The current parameters are `GGM_SIZE=579521` and `HASH_SIZE=5`, which are sufficient for 100 deletions (with only 10^-21 false positive rate) in the test code. Please also update these two parameters when the number of deletion increases by referring to the above Bloom filter calculator.
