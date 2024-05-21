# SDSSE

This repository contains the implementation of SDSSE, the Dynamic Searchable Symmetric Encryption (DSSE) schemes (SDSSE-CQ and SDSSE-CQ-S) we proposed in the PETS submission "*Searchable Encryption for Conjunctive Queries with Extended Forward and Backward Privacy*". The proposed scheme aims to enable conjunctive queries over DSSE schemes with Forward/Backward privacy gurantees. Note that this is a proof-of-concept code implementation and does not include an interactive interface. Instead, we provide a guidance on how to set the parameters to run this code towards various input sizes.

## Requirements

* Git
* Ubuntu version >= 16.04
* gcc/g++ verison>=-5 (5.4.0 in ubuntu 16.04)
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
