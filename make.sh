#! /bin/bash

set -e
set -x

# TODO: make configurable
AFL_PATH="$PWD/afl-2.52b"

python rules2code.py < rules/cxx.txt > rules/cxx.hh
g++ -std=c++11 -I"${AFL_PATH}" -Wall -g -o main main.cc

mkdir -p output
