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
# and captures the traffic, so the suite needs ip, ifconfig, ethtool and
# tcpdump. None of them is in the pinned image: the tag's CI ran on a hosted
# Ubuntu runner where all four were preinstalled, so the tag's version of this
# script never had to name them.
#
# The tests themselves drive an MQTT broker over that link, which is what
# mosquitto and its clients are for, and read the raw device through libpcap at
# -m32.
apt-get install -y --no-install-recommends \
    ethtool \
    iproute2 \
    mosquitto \
    mosquitto-clients \
    net-tools \
    tcpdump \
    libpcap-dev:i386 \
    libgcc-s1:i386
