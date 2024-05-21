cmake_minimum_required(VERSION 3.17)
project(SDSSE)

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
ADD_EXECUTABLE(SSETest Test/SSETest.cpp Core/SSEClientHandler.cpp Core/SSEServerHandler.cpp GGM/GGMTree.cpp BF/Hash/SpookyV2.cpp Util/CommonUtil.c)
add_executable(SDSSECQ SDSSECQ.cpp Core/SDSSECQClient.cpp GGM/GGMTree.cpp BF/Hash/SpookyV2.cpp Util/CommonUtil.c Core/SSEClientHandler.cpp Core/SSEServerHandler.cpp)
add_executable(SDSSECQS SDSSECQS.cpp Core/SDSSECQSClient.cpp GGM/GGMTree.cpp BF/Hash/SpookyV2.cpp Util/CommonUtil.c  Core/SSEClientHandler.cpp Core/SSEServerHandler.cpp)
add_executable(VSDSSECQ GGM/GGMTree.cpp BF/Hash/SpookyV2.cpp Util/CommonUtil.c)

# link
TARGET_LINK_LIBRARIES(AESTest OpenSSL::Crypto)
TARGET_LINK_LIBRARIES(GGMTest OpenSSL::Crypto)
TARGET_LINK_LIBRARIES(SSETest OpenSSL::Crypto)
TARGET_LINK_LIBRARIES(SDSSECQ OpenSSL::Crypto PBC)
TARGET_LINK_LIBRARIES(SDSSECQS OpenSSL::Crypto PBC)
TARGET_LINK_LIBRARIES(VSDSSECQ OpenSSL::Crypto PBC)