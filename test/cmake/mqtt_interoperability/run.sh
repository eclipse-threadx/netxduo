#!/bin/bash

cd $(dirname $0)

. ../dependencies.sh

pin_threadx || exit 1
pin_filex || exit 1

# Recreated on every run, so a link left pointing elsewhere cannot be reused.
ln -sfn ../threadx/scripts/cmake_bootstrap.sh .run.sh

CTEST_PARALLEL_LEVEL=1 ENABLE_IDLE=ON ./.run.sh $*
