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

readonly OPENSSL_VERSION="3.5.7"
readonly OPENSSL_SHA256="a8c0d28a529ca480f9f36cf5792e2cd21984552a3c8e4aa11a24aa31aeac98e8"
readonly OPENSSL_PREFIX="/opt/netxduo/openssl-${OPENSSL_VERSION}"
readonly WOLFSSL_VERSION="5.9.2"
readonly WOLFSSL_SHA256="2f4ef3d4fd387a9b3191d36a6316d69116c46ff69bb9583b6c82b36d7b8ca114"
readonly WOLFSSL_PREFIX="/opt/netxduo/wolfssl-${WOLFSSL_VERSION}"

secure_tmp_dir="$(mktemp -d)"
trap 'rm -rf -- "${secure_tmp_dir}"' EXIT

sudo dpkg --add-architecture i386

sudo apt update
sudo apt install -y \
    gcc-14 \
    g++-14 \
    gcc-14-multilib \
    g++-14-multilib \
    python3-pip \
    build-essential \
    ca-certificates \
    cmake \
    ninja-build \
    perl \
    wget \
    unifdef \
    tofrodos \
    gcovr \
    libpcap-dev:i386 libgcc-s1:i386 \
    ethtool

sudo update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-14 140
sudo update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-14 140
sudo update-alternatives --install /usr/bin/gcov gcov /usr/bin/gcov-14 140

openssl_archive="${secure_tmp_dir}/openssl-${OPENSSL_VERSION}.tar.gz"
wget --quiet --output-document "${openssl_archive}" \
    "https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz"
printf '%s  %s\n' "${OPENSSL_SHA256}" "${openssl_archive}" | sha256sum --check --strict
tar -xzf "${openssl_archive}" -C "${secure_tmp_dir}"
pushd "${secure_tmp_dir}/openssl-${OPENSSL_VERSION}"
./Configure --prefix="${OPENSSL_PREFIX}" --openssldir="${OPENSSL_PREFIX}/ssl" no-shared
make -j"$(nproc)"
sudo make install_sw
popd

wolfssl_archive="${secure_tmp_dir}/wolfssl-${WOLFSSL_VERSION}.tar.gz"
# wolfSSL remains a host-side test executable; NetX Duo does not link to it.
wget --quiet --output-document "${wolfssl_archive}" \
    "https://github.com/wolfSSL/wolfssl/archive/refs/tags/v${WOLFSSL_VERSION}-stable.tar.gz"
printf '%s  %s\n' "${WOLFSSL_SHA256}" "${wolfssl_archive}" | sha256sum --check --strict
tar -xzf "${wolfssl_archive}" -C "${secure_tmp_dir}"
wolfssl_source="${secure_tmp_dir}/wolfssl-${WOLFSSL_VERSION}-stable"
cmake -S "${wolfssl_source}" -B "${secure_tmp_dir}/wolfssl-build" -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_SHARED_LIBS=OFF \
    -DWOLFSSL_OLD_TLS=yes \
    -DWOLFSSL_ECCCUSTCURVES=all \
    -DWOLFSSL_EXAMPLES=yes \
    -DWOLFSSL_CRYPT_TESTS=no \
    "-DCMAKE_C_FLAGS=-DWOLFSSL_STATIC_DH -DHAVE_ECC192 -DHAVE_ECC224 -DWOLFSSL_MIN_ECC_BITS=192 -DDEFAULT_MIN_ECCKEY_BITS=192"
cmake --build "${secure_tmp_dir}/wolfssl-build" --target server --parallel "$(nproc)"
sudo install -D -m 0755 "${secure_tmp_dir}/wolfssl-build/examples/server/server" \
    "${WOLFSSL_PREFIX}/bin/wolfssl-server"
sudo install -D -m 0644 "${wolfssl_source}/certs/dh2048.pem" \
    "${WOLFSSL_PREFIX}/share/wolfssl/certs/dh2048.pem"

"${OPENSSL_PREFIX}/bin/openssl" version -v
pushd "${WOLFSSL_PREFIX}/share/wolfssl"
"${WOLFSSL_PREFIX}/bin/wolfssl-server" --help 2>&1 | sed -n '1p'
popd
