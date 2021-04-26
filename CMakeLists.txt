cmake_minimum_required(VERSION 3.17)
project(FBDSSE)

set(CMAKE_CXX_STANDARD 14)

FIND_PACKAGE(OpenSSL REQUIRED)

# load header
INCLUDE_DIRECTORIES(. BF BF/Hash GGM Util Util/PBC)

# add link directory for pbc
LINK_DIRECTORIES(Util/PBC)

ADD_LIBRARY(PBC STATIC
        Util/PBC/G.cc
        Util/PBC/G1.cc
        Util/PBC/G2.cc
        Util/PBC/GT.cc
        Util/PBC/Pairing.cc
        Util/PBC/PPPairing.cc
        Util/PBC/Zr.cc)

TARGET_LINK_LIBRARIES(PBC -lgmp -lpbc)

# set executable outputs
ADD_EXECUTABLE(AESTest Test/AESTest.cpp Util/CommonUtil.c)
ADD_EXECUTABLE(BloomFilterTest Test/BloomFilterTest.cpp BF/Hash/SpookyV2.cpp)
ADD_EXECUTABLE(GGMTest Test/GGMTest.cpp GGM/GGMTree.cpp Util/CommonUtil.c)
add_executable(SDSSECQ SDSSECQ.cpp Core/SDSSECQClient.cpp Core/SDSSECQServer.cpp GGM/GGMTree.cpp BF/Hash/SpookyV2.cpp Util/CommonUtil.c)

# link
TARGET_LINK_LIBRARIES(AESTest OpenSSL::Crypto)
TARGET_LINK_LIBRARIES(GGMTest OpenSSL::Crypto)
TARGET_LINK_LIBRARIES(SDSSECQ OpenSSL::Crypto PBC)