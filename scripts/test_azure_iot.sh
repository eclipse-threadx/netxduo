#! /bin/bash

CTEST_PARALLEL_LEVEL=4 $(dirname `realpath $0`)/../test/cmake/azure_iot/run.sh test all
