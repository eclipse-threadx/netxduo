#!/bin/bash

cd $(dirname $0)

[ -f .run.sh ] || ln -sf ../threadx/scripts/cmake_bootstrap.sh .run.sh
PTP_ONLY=ON ./.run.sh $*
