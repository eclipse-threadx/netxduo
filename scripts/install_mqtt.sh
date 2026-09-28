#! /bin/bash
#
# Dependencies for the MQTT interoperability suite, on top of the common ones.
#
# The toolchain is not installed again here. install.sh defines it and asserts
# its versions, and this script sources it, so the two interoperability jobs
# cannot end up on a different gcc, CMake or gcovr from the eight that use
# install.sh directly.

set -eux

. "$(dirname "$(realpath "$0")")/install.sh"

# Each test builds a veth pair, addresses it, disables transmit offload on it
# and captures the traffic, so the suite needs ip, ethtool and tcpdump. None of
# them is in the pinned image: the tag's CI ran on a hosted Ubuntu runner where
# all three were preinstalled, so the tag's version of this script never had to
# name them.
#
# net-tools is deliberately absent. The suite addressed its veth pair with
# ifconfig until the test surface was modernised; it now uses ip for both the
# link and the address, so nothing invokes ifconfig any more.
#
# The tests themselves drive an MQTT broker over that link, which is what
# mosquitto and its clients are for, and read the raw device through libpcap at
# -m32. The broker links the image's own libssl; nothing in this suite invokes
# an openssl binary, so it needs neither the package nor the pinned build the
# TLS suite makes.
apt-get install -y --no-install-recommends \
    ethtool \
    iproute2 \
    mosquitto \
    mosquitto-clients \
    tcpdump \
    libpcap-dev:i386 \
    libgcc-s1:i386
