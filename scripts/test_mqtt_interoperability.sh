#! /bin/bash

sudo CTEST_PARALLEL_LEVEL=1 $(dirname `realpath $0`)/../test/cmake/mqtt_interoperability/run.sh test all
