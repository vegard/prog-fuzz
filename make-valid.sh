#! /bin/bash

set -e
set -x

# TODO: make configurable
AFL_PATH="$PWD/afl-2.52b"

g++ -std=c++14 -Wall -Wno-unused-function -I"${AFL_PATH}" -O2 -g -o main-valid main-valid.cc

mkdir -p output
