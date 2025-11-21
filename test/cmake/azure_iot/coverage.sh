#!/bin/bash

set -e

cd $(dirname $0)
mkdir -p coverage_report/$1
gcovr --object-directory=build/$1/netxduo/CMakeFiles/netxduo.dir/addons/azure_iot -r ../../../addons/azure_iot --xml-pretty --output coverage_report/$1.xml
gcovr --object-directory=build/$1/netxduo/CMakeFiles/netxduo.dir/addons/azure_iot -r ../../../addons/azure_iot --html --html-details --output coverage_report/$1/index.html
