#! /bin/bash
#
# Dependencies for the TLS interoperability suite, on top of the common ones.
#
# The toolchain is not installed again here. install.sh defines it and asserts
# its versions, and this script sources it, so the two interoperability jobs
# cannot end up on a different gcc, CMake or gcovr from the eight that use
# install.sh directly.

set -eux

script_dir=$(dirname "$(realpath "$0")")
. "$script_dir/install.sh"

# Each test builds a veth pair, addresses it, disables transmit offload on it
# and captures the traffic, so the suite needs ip, ethtool and tcpdump, and
# demo_ping_test launches ping. None of them is in the pinned image: the tag's
# CI ran on a hosted Ubuntu runner where all four were preinstalled, so the
# tag's version of this script never had to name them. make and perl build
# OpenSSL below.
#
# net-tools is deliberately absent. The suite addressed its veth pair with
# ifconfig until the test surface was modernised; it now uses ip for both the
# link and the address, so nothing invokes ifconfig any more.
apt-get install -y --no-install-recommends \
    ethtool \
    iproute2 \
    iputils-ping \
    make \
    perl \
    tcpdump \
    libpcap-dev:i386 \
    libgcc-s1:i386

# The suite handshakes NetX Duo against two independent TLS implementations,
# and both are built here from a recorded version with a verified digest.
#
# OpenSSL serves the modern protocol versions. wolfSSL serves the legacy ones:
# it is configured WOLFSSL_OLD_TLS=yes with 192- and 224-bit ECC enabled, which
# is what keeps a peer for TLS 1.0 and 1.1 now that a current OpenSSL will not
# complete those handshakes at its default security level.
#
# The wrappers under nx_secure_test/test_scripts resolve both binaries under
# /opt/netxduo by default, so these prefixes are a contract with them rather
# than a packaging choice. Each is overridable by NETXDUO_OPENSSL_BIN,
# NETXDUO_WOLFSSL_SERVER_BIN and NETXDUO_WOLFSSL_HOME.
openssl_version=3.5.7
openssl_sha256=a8c0d28a529ca480f9f36cf5792e2cd21984552a3c8e4aa11a24aa31aeac98e8
openssl_prefix=/opt/netxduo/openssl-$openssl_version

wolfssl_version=5.9.2
wolfssl_sha256=2f4ef3d4fd387a9b3191d36a6316d69116c46ff69bb9583b6c82b36d7b8ca114
wolfssl_prefix=/opt/netxduo/wolfssl-$wolfssl_version

work_dir=$(mktemp -d)
trap 'rm -rf -- "$work_dir"' EXIT

# Digest checked before anything is unpacked, in both cases. The tag fetched
# its one peer over an unverified wget from a URL that has since started
# redirecting, which is the reason this is not left to the transport.
openssl_archive=$work_dir/openssl-$openssl_version.tar.gz
wget -q -O "$openssl_archive" \
    "https://github.com/openssl/openssl/releases/download/openssl-$openssl_version/openssl-$openssl_version.tar.gz"
echo "$openssl_sha256  $openssl_archive" | sha256sum -c -
tar -xzf "$openssl_archive" -C "$work_dir"

# Built static and under its own prefix, so a second libcrypto cannot shadow
# the image's for anything else. install_sw rather than install, because the
# man pages are the slowest part and nothing reads them.
(
    cd "$work_dir/openssl-$openssl_version"
    ./Configure --prefix="$openssl_prefix" --openssldir="$openssl_prefix/ssl" no-shared
    make -j"$(nproc)"
    make install_sw
)

wolfssl_archive=$work_dir/wolfssl-$wolfssl_version.tar.gz
wget -q -O "$wolfssl_archive" \
    "https://github.com/wolfSSL/wolfssl/archive/refs/tags/v$wolfssl_version-stable.tar.gz"
echo "$wolfssl_sha256  $wolfssl_archive" | sha256sum -c -
tar -xzf "$wolfssl_archive" -C "$work_dir"

# wolfSSL is a host-side test peer only. NetX Duo does not link against it and
# none of it reaches the certified library.
wolfssl_source=$work_dir/wolfssl-$wolfssl_version-stable
cmake -S "$wolfssl_source" -B "$work_dir/wolfssl-build" -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_SHARED_LIBS=OFF \
    -DWOLFSSL_OLD_TLS=yes \
    -DWOLFSSL_ECCCUSTCURVES=all \
    -DWOLFSSL_EXAMPLES=yes \
    -DWOLFSSL_CRYPT_TESTS=no \
    "-DCMAKE_C_FLAGS=-DWOLFSSL_STATIC_DH -DHAVE_ECC192 -DHAVE_ECC224 -DWOLFSSL_MIN_ECC_BITS=192 -DDEFAULT_MIN_ECCKEY_BITS=192"
cmake --build "$work_dir/wolfssl-build" --target server --parallel "$(nproc)"
install -D -m 0755 "$work_dir/wolfssl-build/examples/server/server" \
    "$wolfssl_prefix/bin/wolfssl-server"
install -D -m 0644 "$wolfssl_source/certs/dh2048.pem" \
    "$wolfssl_prefix/share/wolfssl/certs/dh2048.pem"

# verify_test_certificates.sh runs as a test of its own and resolves openssl
# from the ambient PATH rather than through the suite's wrapper, so the pinned
# build is put where that finds it. The image installs no openssl package, and
# /usr/local/bin precedes /usr/bin, so this is the only openssl on the PATH and
# the certificate evidence is produced by the recorded version. The wrapper is
# unaffected: the tests prepend test_scripts/ to PATH and reach it first.
ln -sf "$openssl_prefix/bin/openssl" /usr/local/bin/openssl

# Asserted rather than printed, for the same reason install.sh asserts its
# three: an interoperability result is only evidence if the peer it was taken
# against is the peer that was recorded.
#
# wolfssl-server resolves its certificate paths relative to the wolfSSL home
# and refuses to start anywhere else, so its version is read from that
# directory -- which is also where the suite's wrapper runs it.
openssl version -v
openssl_reported=$(openssl version)
case "$openssl_reported" in
    "OpenSSL $openssl_version"*) ;;
    *) echo "install_secure.sh: expected OpenSSL $openssl_version, got $openssl_reported" >&2; exit 1 ;;
esac

wolfssl_reported=$(cd "$wolfssl_prefix/share/wolfssl" && \
    "$wolfssl_prefix/bin/wolfssl-server" --help 2>&1 | sed -n '1p')
echo "$wolfssl_reported"
case "$wolfssl_reported" in
    "server $wolfssl_version "*) ;;
    *) echo "install_secure.sh: expected wolfSSL $wolfssl_version, got $wolfssl_reported" >&2; exit 1 ;;
esac
