#! /bin/bash

sudo dpkg --add-architecture i386

sudo cp /usr/bin/openssl /usr/bin/openssl-1.1

sudo apt update
sudo apt install -y \
    gcc-multilib \
    g++ \
    python3-pip \
    ninja-build \
    unifdef \
    tofrodos \
    gcovr \
    libpcap-dev:i386 libgcc-s1:i386 \
    ethtool

wget https://www.openssl.org/source/old/1.0.2/openssl-1.0.2n.tar.gz
tar -xzvf openssl-1.0.2n.tar.gz
cd openssl-1.0.2n
sudo ./config
sudo make install

sudo ln -sf /usr/local/ssl/bin/openssl /usr/bin/openssl

openssl version -v
