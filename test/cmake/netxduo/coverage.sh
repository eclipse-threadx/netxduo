#!/bin/bash

set -e

cd $(dirname $0)
root_path=$(cd ../../../common/src; pwd)
mkdir -p coverage_report/$1
gcovr --object-directory=build/$1/netxduo/CMakeFiles/netxduo.dir/common/src -r ../../../common/src -e $root_path/nx_ram_network_driver.c --xml-pretty --output coverage_report/$1.xml
gcovr --object-directory=build/$1/netxduo/CMakeFiles/netxduo.dir/common/src -r ../../../common/src -e $root_path/nx_ram_network_driver.c --html --html-details --output coverage_report/$1/index.html
