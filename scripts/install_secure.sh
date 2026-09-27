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
# and captures the traffic, so the suite needs ip, ifconfig, ethtool and
# tcpdump. None of them is in the pinned image: the tag's CI ran on a hosted
# Ubuntu runner where all four were preinstalled, so the tag's version of this
# script never had to name them. make and perl are for the OpenSSL build below.
apt-get install -y --no-install-recommends \
    ethtool \
    iproute2 \
    make \
    net-tools \
    openssl \
    perl \
    tcpdump \
    libpcap-dev:i386 \
    libgcc-s1:i386

# The suite handshakes NetX Duo against two OpenSSL peers, and it needs both.
#
# openssl-1.1 is the distribution's own, and it serves the nine TLS 1.3 tests.
# openssl is 1.0.2, and it serves the other twenty-four: twenty-nine of the
# tests select -tls1 and twenty-nine -tls1_1, and a current OpenSSL will not
# speak either at its default security level. Substituting the modern one would
# not make those tests pass differently, it would stop them exercising the
# protocol versions they exist to exercise.
cp /usr/bin/openssl /usr/bin/openssl-1.1

# The tag fetched this tarball from openssl.org/source/old/ and built it with no
# integrity check of any kind, on the branch whose purpose is a reproducible
# build environment. The fetch stays -- 1.0.2 is not packaged by any current
# distribution and vendoring five megabytes of a third party's source into this
# repository would be worse -- but it is pinned: one version, one recorded
# digest, verified before anything is unpacked, and the built binary's version
# asserted afterwards. That URL now redirects to the project's GitHub release
# assets, which is itself the reason not to trust an unverified download.
#
# Built static, which is what 1.0.2's config produces without "shared": the
# result links nothing but libc, so a 2017 libcrypto cannot shadow the system
# one for anything else in the image. install_sw rather than install, because
# the man pages are the slowest part of the install and nothing reads them.
openssl_version=1.0.2n
openssl_sha256=370babb75f278c39e0c50e8c4e7493bc0f18db6867478341a832a982fd15a8fe

cd "$(mktemp -d)"
wget -q "https://www.openssl.org/source/old/1.0.2/openssl-$openssl_version.tar.gz"
echo "$openssl_sha256  openssl-$openssl_version.tar.gz" | sha256sum -c -
tar -xzf "openssl-$openssl_version.tar.gz"
cd "openssl-$openssl_version"
./config
make -j"$(nproc)"
make install_sw

ln -sf /usr/local/ssl/bin/openssl /usr/bin/openssl

openssl version -v
openssl-1.1 version -v

case "$(openssl version)" in
    "OpenSSL $openssl_version"*) ;;
    *) echo "install_secure.sh: expected OpenSSL $openssl_version, got $(openssl version)" >&2; exit 1 ;;
esac
