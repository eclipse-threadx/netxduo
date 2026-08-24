#!/bin/bash
##############################################################################
# Copyright (c) 2024 Microsoft Corporation
# Copyright (c) 2026 Eclipse ThreadX contributors
#
# This program and the accompanying materials are made available under the
# terms of the MIT License which is available at
# https://opensource.org/licenses/MIT.
#
# SPDX-License-Identifier: MIT
##############################################################################

cd $(dirname $0)

# if threadx repo does not exist, clone it
[ -d ../threadx ] || git clone https://github.com/eclipse-threadx/threadx.git ../threadx --depth 1
[ -d ../filex ] || git clone https://github.com/eclipse-threadx/filex.git ../filex --depth 1
[ -f .run.sh ] || ln -sf ../threadx/scripts/cmake_bootstrap.sh .run.sh
CTEST_PARALLEL_LEVEL=1 ENABLE_IDLE=ON ./.run.sh $*
