cmake_minimum_required(VERSION 3.17)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wpedantic -Wshadow")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Wpedantic -Wshadow")

if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

#if debug, add asan
if (CMAKE_BUILD_TYPE MATCHES Debug)
    message(STATUS "Debug build")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -O0 -fsanitize=address,undefined")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -O0 -fsanitize=address,undefined")
endif()

if (CMAKE_BUILD_TYPE MATCHES Release)
    message(STATUS "Release build")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O3")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -flto -ffat-lto-objects -fuse-linker-plugin")
endif()

set(VCPKG_ROOT "${CMAKE_SOURCE_DIR}/extern/vcpkg")
if (WIN32)
    find_program(VCPKG_EXE "${VCPKG_ROOT}/vcpkg.exe")
else()
    find_program(VCPKG_EXE "${VCPKG_ROOT}/vcpkg")
endif()
set(CMAKE_TOOLCHAIN_FILE "${VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake" CACHE PATH "VCPKG toolchain file")

project(SDSSE)
set(CMAKE_C_STANDARD 23)
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_package(OpenSSL REQUIRED)
find_package(PkgConfig REQUIRED)
find_package(msgpack-cxx REQUIRED)
find_package(args CONFIG REQUIRED)
pkg_check_modules(gmp REQUIRED IMPORTED_TARGET gmp)

find_path(PBC_INCLUDE_DIR pbc/pbc.h)
include_directories(${PBC_INCLUDE_DIR})
message(STATUS "PBC_INCLUDE_DIR: ${PBC_INCLUDE_DIR}")

find_library(PBC_LIBRARY NAMES pbc HINTS ${CMAKE_PREFIX_PATH} PATH_SUFFIXES lib)
message(STATUS "PBC_LIBRARY: ${PBC_LIBRARY}")

# load header
include_directories(. BF BF/Hash GGM Util Util/PBC)

# add link directory for pbc
link_directories(Util/PBC)

ADD_LIBRARY(PBCWrapper STATIC
        Util/PBC/G.cc
        Util/PBC/G1.cc
        Util/PBC/G2.cc
        Util/PBC/GT.cc
        Util/PBC/Pairing.cc
        Util/PBC/PPPairing.cc
        Util/PBC/Zr.cc)
TARGET_LINK_LIBRARIES(PBCWrapper ${PBC_LIBRARY} PkgConfig::gmp)

# set executable outputs
ADD_EXECUTABLE(SM4Test Test/SM4Test.cpp Util/CommonUtil.c)
ADD_EXECUTABLE(BloomFilterTest Test/BloomFilterTest.cpp BF/Hash/SpookyV2.cpp BF/BloomFilter.cpp)
ADD_EXECUTABLE(GGMTest Test/GGMTest.cpp GGM/GGMTree.cpp Util/CommonUtil.c)
ADD_EXECUTABLE(SSETest Test/SSETest.cpp Core/SSEClientHandler.cpp Core/SSEServerHandler.cpp GGM/GGMTree.cpp BF/Hash/SpookyV2.cpp BF/BloomFilter.cpp Util/CommonUtil.c)
add_executable(SDSSECQ SDSSECQ.cpp Core/SDSSECQClient.cpp GGM/GGMTree.cpp BF/Hash/SpookyV2.cpp BF/BloomFilter.cpp Util/CommonUtil.c Core/SSEClientHandler.cpp Core/SSEServerHandler.cpp)
add_executable(SDSSECQS SDSSECQS.cpp Core/SDSSECQSClient.cpp GGM/GGMTree.cpp BF/Hash/SpookyV2.cpp BF/BloomFilter.cpp Util/CommonUtil.c  Core/SSEClientHandler.cpp Core/SSEServerHandler.cpp)
ADD_EXECUTABLE(SSEServerStandalone Server/SSEServerStandalone.cpp Core/SSEServerHandler.cpp GGM/GGMTree.cpp BF/Hash/SpookyV2.cpp BF/BloomFilter.cpp Util/CommonUtil.c)
add_executable(SDSSECQSCLI SDSSECQSCLI.cpp Core/SDSSECQSClient.cpp GGM/GGMTree.cpp BF/Hash/SpookyV2.cpp BF/BloomFilter.cpp Util/CommonUtil.c Core/SSEClientHandler.cpp Core/SSEServerHandler.cpp)

# link
TARGET_LINK_LIBRARIES(SM4Test OpenSSL::Crypto)
TARGET_LINK_LIBRARIES(GGMTest OpenSSL::Crypto)
TARGET_LINK_LIBRARIES(SSETest OpenSSL::Crypto)
TARGET_LINK_LIBRARIES(SDSSECQ OpenSSL::Crypto PBCWrapper msgpack-cxx)
TARGET_LINK_LIBRARIES(SDSSECQS OpenSSL::Crypto PBCWrapper msgpack-cxx)
TARGET_LINK_LIBRARIES(SSEServerStandalone OpenSSL::Crypto msgpack-cxx pthread taywee::args)
TARGET_LINK_LIBRARIES(SDSSECQSCLI OpenSSL::Crypto PBCWrapper msgpack-cxx taywee::args)

install(TARGETS SM4Test BloomFilterTest GGMTest SSETest SDSSECQ SDSSECQS SSEServerStandalone SDSSECQSCLI
        RUNTIME DESTINATION bin)
