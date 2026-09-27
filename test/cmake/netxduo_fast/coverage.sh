#!/bin/bash

set -e

cd $(dirname $0)

# The certified denominator is common/src less nx_ram_network_driver.c, the
# harness's simulated Ethernet device. gcovr's -r is what confines the report:
# the instrumented library also holds nx_secure, crypto_libraries and addons.
root_path=$(cd ../../../common/src; pwd)
mkdir -p coverage_report/$1
gcovr --object-directory=build/$1/netxduo/CMakeFiles/netxduo.dir/common/src -r ../../../common/src -e $root_path/nx_ram_network_driver.c --xml-pretty --output coverage_report/$1.xml
gcovr --object-directory=build/$1/netxduo/CMakeFiles/netxduo.dir/common/src -r ../../../common/src -e $root_path/nx_ram_network_driver.c --html --html-details --output coverage_report/$1/index.html
