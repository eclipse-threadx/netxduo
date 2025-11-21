#! /bin/bash

sudo dpkg --add-architecture i386

sudo apt update
sudo apt install -y \
    gcc-multilib \
    g++ \
    python3-pip \
    ninja-build \
    unifdef \
    dos2unix \
    gcovr \
    libpcap-dev:i386 libgcc-s1:i386 \
    ethtool \
    mosquitto \
    mosquitto-clients