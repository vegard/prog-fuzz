#! /bin/bash

set -e
set -x

# TODO: make configurable
AFL_PATH="/home/vegard/afl.rs/afl-2.52b/"

python rules2code.py < rules/rust.txt > rules/cxx.hh
g++ -std=c++11 -I"${AFL_PATH}" -Wall -g -o main main.cc

mkdir -p output
