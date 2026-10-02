#! /bin/bash
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


sudo dpkg --add-architecture i386

sudo apt update
sudo apt install -y \
    gcc-14 \
    g++-14 \
    gcc-14-multilib \
    g++-14-multilib \
    python3-pip \
    ninja-build \
    unifdef \
    dos2unix \
    gcovr \
    libpcap-dev:i386 libgcc-s1:i386 \
    ethtool \
    mosquitto \
    mosquitto-clients

sudo update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-14 140
sudo update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-14 140
sudo update-alternatives --install /usr/bin/gcov gcov /usr/bin/gcov-14 140
