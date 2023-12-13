#!/bin/bash

set -e

cd $(dirname $0)
mkdir -p coverage_report/$1
gcovr --object-directory=build/$1/netxduo/CMakeFiles/netxduo.dir/crypto_libraries -r ../../../crypto_libraries --xml-pretty --output coverage_report/$1.xml
gcovr --object-directory=build/$1/netxduo/CMakeFiles/netxduo.dir/crypto_libraries -r ../../../crypto_libraries --html --html-details --output coverage_report/$1/index.html
