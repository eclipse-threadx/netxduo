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

set -euo pipefail

# Install the host tools used by the CMake regression suites on Ubuntu 24.04.
readonly GCOVR_VERSION="8.6"
readonly GCOVR_PREFIX="/opt/netxduo/gcovr-${GCOVR_VERSION}"

sudo dpkg --add-architecture i386
sudo apt-get update
sudo apt-get install -y \
    gcc-14 \
    g++-14 \
    gcc-14-multilib \
    g++-14-multilib \
    git \
    cmake \
    ninja-build \
    python3-venv \
    unifdef \
    p7zip-full \
    tofrodos \
    dos2unix \
    gawk \
    libssl-dev:i386 \
    libcmocka-dev:i386 \
    gcc-arm-none-eabi

sudo update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-14 140
sudo update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-14 140
sudo update-alternatives --install /usr/bin/gcov gcov /usr/bin/gcov-14 140

# gcovr 8.x is required for GCC 14's coverage data and JSON gcov format.
sudo python3 -m venv "${GCOVR_PREFIX}"
sudo "${GCOVR_PREFIX}/bin/python" -m pip install \
    --disable-pip-version-check \
    --no-cache-dir \
    "gcovr==${GCOVR_VERSION}"
sudo ln -sfn "${GCOVR_PREFIX}/bin/gcovr" /usr/local/bin/gcovr
