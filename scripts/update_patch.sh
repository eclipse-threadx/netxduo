#!/bin/bash

if [ "$#" -ne 2 ]; then
    echo "Usage: $0 \"<version>\" \"<date>\""
    exit 1
fi

cd $(dirname `realpath $0`)/..
current_version="6\\.x"
source_dirs="addons common crypto_libraries nx_secure ports test"
file_list=$(find $source_dirs -path netxduo/addons/azure_iot -prune -o -type f -name '*.[ch]' -print)

sed -i "s/$current_version  /$1/g" $file_list
sed -i "s/$current_version/$1/g" $file_list
sed -i "s/xx-xx-xxxx/$2/g" $file_list
sed -i "s/xx\/xx\/xxxx/${2:0:2}\/${2:3:2}\/${2:6:4}/g" readme/*

# Update version in port files
source_dirs="ports nx_secure/ports"
file_list=$(find $source_dirs -type f -name "*.h" -print)
sed -i "/\"Copyright/,/[0-9]\.[0-9]/s/[0-9]\.[0-9\.]\+/$1/" $file_list