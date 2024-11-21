# Artifact Appendix

Paper title: **Searchable Encryption for Conjunctive Queries with Extended Forward and Backward Privacy**

Artifacts HotCRP Id: **#12**

Requested Badge: **Reproduced**

## Description
This repository contains the implementation of SDSSE, the Dynamic Searchable Symmetric Encryption (DSSE) schemes (SDSSE-CQ and SDSSE-CQ-S) we proposed in the PETS submission "Searchable Encryption for Conjunctive Queries with Extended Forward and Backward Privacy".
The proposed scheme aims to enable conjunctive queries over DSSE schemes with Forward/Backward privacy gurantees.

### Security/Privacy Issues and Ethical Concerns

This artifact will not cause any risk to the security or privacy of the reviewer's machine.
The artifact will not lead to ethical concerns because:
1. It leverages open-source software with proper licenses for the implementation.
2. As a privacy-enhancing design, the artifact contributes positively to the society by fortifying
   data privacy in the cloud.

## Environment

### Accessibility
Our code is available in GitHub. Please access the code via this [link](https://github.com/MonashCybersecurityLab/SDSSE).

You may use the following command to pull the code to your local machine:
```bash
git clone https://github.com/MonashCybersecurityLab/SDSSE.git
```

### Set up the environment
**Requirements**

* Git
* Ubuntu version >= 16.04
* gcc/g++ version>=-5 (5.4.0 in ubuntu 16.04)
* cmake >= 3.17
* openssl version >= 1.1.0h
* The Pairing-Based Cryptography Library (PBC) version 0.5.14

#### Some Notes for the System Requirements

1. The above setting represents the oldest version we tested with our implementation. We cannot guarantee the code will be compatible with any environments that are older than the above environment settings. On the other hand, although the code has been tested in some newer environments, including Ubuntu 20.04 and gcc/g++ 9.0, we still cannot guarantee its correctness on the latest version of above software, especially because some openssl APIs are deprecated.

2. The implementation cannot run with MacOS because the file system (APFS) of MacOS is not case-sensitive. This creates a collision between the PBC C++ Wrapper and the original PBC library, making the building toolkit unable to build the required library correctly. This issue cannot be addressed even if we run a Docker container upon MacOS since it inherits the underlying file system features. To address this issue, the only solution is to re-format your MacOS file system to APFS (case-sensitive), but this will create incompatibility on some native MacOS software. Hence, we do not recommend to running our code with MacOS.

#### Setup Process
We provide two ways to set up the environment for this artifact:

**Option 1: Docker Container**

This artifact provides the docker container to run the code.
After downloading the artifact, please use the following command to build the docker container:
```bash
cd SDSSE/Container
docker compose up
```
After building the container, use the following command to connect to the container:
```bash
docker exec -it SDSSE-dev sh
```
The source code will be mapped to the path `~/SDSSE` inside the container.

**Option 2: Use a Physical Machine**

The `Dockerfile` under `SDSSE/Container` provides a list of necessary software to run the code and how to install them.
Following the list, you can setup a bare-metal server to compile our code.

#### Build the Code
Run the following commands to build the code:

```bash
cd SDSSE
mkdir build
cd build
# use cmake to build the code
cmake ..
cmake --build . --target [SDSSECQ|SDSSECQS]
```

### Test the environment
After compiling the project, you can run the following commands to start the test program:
```bash
cd ../Data
../build/[SDSSECQ|SDSSECQS] [w1 size] [w2 size] [Deletion Size]
```
For instance, the following command sets an encrypted database on `SDSSECQ` with keyword-id pairs `(w1, i), 0 <= i <= 9` and `(w2, i), 0 <= i <= 4`, and deletes `(w1, 0)` and `(w2, 0)` (10% deletion).
It then performs a single keyword search over `w1` and a conjunctive one with `w1` and `w2`.
```bash
cd ../Data
../build/SDSSECQ 10 5 1
```

If you experience runtime errors, indicating that the libpbc cannot be found in your system, please run the following command to check `LD_LIBRARY_PATH`:
```bash
echo $LD_LIBRARY_PATH
```
to ensure the path `usr/local/lib` is in that environment variable. You may need to manually add it in if there is no such path inside and meet the corresponding runtime error.

## Artifact Evaluation

### Parameters
As mentioned, the current implementation is a proof-of-concept prototype.To evaluate the proposed protocol, we also implement two test programs to generate synthesis datasets and run our proposed DSSE protocol over them.

#### Dataset Size
The source code of those test programs can be found in the root path of the project, namely `SDSSECQ.cpp` and `SDSSECQS.cpp`. The code in this repository inserts files with two keywords "Alice" and "Bob", deletes specific amount of the inserted files, and then executes one single keyword query ("Alice") and a conjunctive query ("Alice" AND "Bob").
The parameters used to specify the number of insertions/deletions are set as program arguments when running those programs as shown in the above section.

Besides, as the number of keyword-id pairs increases, we should use a larger Bloom filter to keep the XSet for conjunctive queries. Hence, the `MAX_DB_SIZE`, `XSET_FP`, and `XSET_HASH` in `Util
/CommonUtil.h` should be updated accordingly. Note that the current parameters `MAX_DB_SIZE=100000`, `XSET_FP=0.0000001` and `XSET_HASH=20` can support conjunctive queries against a dataset with 100k keyword-id pairs with less than 10^-7 false positive rate. 

#### Deletion
Since the deletion is also based on Bloom filter, there are another two Bloom filter parameters, i.e., `GGM_FP` and `HASH_SIZE` to be set to help the code automatically derive the Bloom filter size for the GGM tree.
The current parameters are `GGM_FP=0.0001` and `HASH_SIZE=5`, which is designed to achieve 10^-4 false positive rate with the 5 hash functions in the test code. Please also update these two parameters if you are looking for a smaller false positive rate or GGM tree size (more hash functions lead to a smaller tree).

### Main Results and Claims

#### Automatic Benchmarking Script
We provide a script for automatic benchmarking.
The script can be executed with the following command under the `Data` folder:
```bash
./Evaluation
```
It will automatically execute required commands to reproduce the following results.

#### Main Result 1: Constant and Small Time For Insertion/Deletion
As shown in `Table 3`, after fixing the parameter, the insertion time and deletion time for each `(keyword, id)` is a constant.
Please refer to `Experiment 1` to see how to reproduce the result.

#### Main Result 2: The search time is linear
As shown in `Figure 3-7`, if a proper parameter is set for the scheme, the query delay is linear to the variable, i.e., |w1| and |w2|.
Please refer to `Experiment 2, 3 and 4` to see how to reproduce the result.

### Experiments

#### Experiment 1: Insertion and Deletion Time
After setting the parameter as in the `Parameters` section, re-build the code with the instructions in the `Build the Codes`.
Then, execute the following command under the `Data` folder.
```bash
../build/[SDSSECQ|SDSSECQS] [w1 size] [w2 size] [Deletion Size]
```
The time per insertion and per deletion will be printed in microseconds.

#### Experiment 2: Search Time with Constant |w1|
To reproduce the search time cost, please follow the `Parameters` section to set the Bloom filter size to ensure
a 10^-4 false positive rate.
Then, re-build the code with the instructions in the `Build the Codes`, and execute the following command under the `Data` folder to
reproduce the result in `Figure 3` (Constant |w1| with no deletion)
```bash
../build/[SDSSECQ|SDSSECQS] 10 [w2 size] 0
```

Then, execute the following command under the `Data` folder to
reproduce the result in `Figure 4` (Constant |w1| with 10% deletion)
```bash
../build/[SDSSECQ|SDSSECQS] 10 [w2 size] 1
```

For both tests, `[w2 size]` should be pick from `[10, 100, 1000, 10000, 100000]` to observe the linear trend.

#### Experiment 3: Search Time with Constant |w2|
Similar to `Experiment 2`, `Experiment 3` should follow the `Parameters` section to set the Bloom filter size.
Then, re-build the code with the instructions in the `Build the Codes`, and execute the following command under the `Data` folder to
reproduce the result in Figure 5 (Constant |w2| with no deletion)
```bash
../build/[SDSSECQ|SDSSECQS] [w1 size] 10 0
```

Then, execute the following command under the `Data` folder to
reproduce the result in Figure 6 (Constant |w2| with 10% deletion)
```bash
../build/[SDSSECQ|SDSSECQS] [w1 size] 10 [Deletion Size]
```
For both tests, `[w1 size]` should be pick from `[10, 100, 1000, 10000, 100000]` and
`[Deletion Size]` should be 10% of the chosen `[w1 size]` to observe the linear trend.

#### Experiment 4: Search Time Single Keyword
Similar to `Experiment 2`, `Experiment 4` should follow the `Parameters` section to set the Bloom filter size.
Then, re-build the code with the instructions in the `Build the Codes`, and execute the following command under the `Data` folder to
reproduce the result in Figure 7 (Single keyword search with no deletion and 10% deletion)
```bash
../build/[SDSSECQ|SDSSECQS] [w1 size] 0 0
../build/[SDSSECQ|SDSSECQS] [w1 size] 0 [Deletion Size]
```
For the both tests, `[w1 size]` should be pick from `[10, 100, 1000, 10000, 100000]`, and for the 10% deletion test,
`[Deletion Size]` should be 10% of the chosen `[w1 size]` to observe the linear trend.

## Limitations
1. The communication cost of the proposed scheme in `Table 4-6` is not shown in this artifact because it can be easily calculated based on
   the data structures defined in the implementation.
2. This artifact does not include the implementation of schemes compared in this paper, such as `IM-DSSE` and `ODXT`, we leverage the open-source
   implementation published in GitHub and the results published in prior works for our evaluation.
   In particular, `IM-DSSE` can be found in [here](https://github.com/thanghoang/IM-DSSE), and we use the result in the `ODXT` paper
   ([here](https://eprint.iacr.org/2020/1342.pdf)) as our testbed has a similar specification.

## Notes on Reusability
This is a proof-of-concept code implementation and does not include an interactive interface or any real dataset. However,
as a DSSE scheme, our implementation provides the interface to take `(keyword, id)` pairs as the input.
Hence, it can be easily extended to store different datasets by preprocessing these datasets to `(keyword, id)` pairs.
Also, as general DSSE protocols, our scheme can be used to implement real encrypted databases, the corresponding
insertion/deletion and query interfaces are given for this purpose.