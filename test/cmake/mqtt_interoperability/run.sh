eclipse-threadx#!/bin/bash

cd $(dirname $0)

[ -f .run.sh ] || ln -sf ../threadx/scripts/cmake_bootstrap.sh .run.sh
CTEST_PARALLEL_LEVEL=1 ENABLE_IDLE=ON ./.run.sh $*
