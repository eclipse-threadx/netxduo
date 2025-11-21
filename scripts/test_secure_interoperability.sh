#! /bin/bash

sudo CTEST_PARALLEL_LEVEL=1 $(dirname `realpath $0`)/../test/cmake/nx_secure_interoperability/run.sh test all
