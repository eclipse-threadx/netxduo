#!/bin/bash

cd $(dirname $0)

. ../dependencies.sh

pin_threadx || exit 1
pin_filex || exit 1

# Recreated on every run, so a link left pointing elsewhere cannot be reused.
ln -sfn ../threadx/scripts/cmake_bootstrap.sh .run.sh

ENABLE_64=ON ./.run.sh $*
