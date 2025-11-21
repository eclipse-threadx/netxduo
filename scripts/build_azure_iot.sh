#! /bin/bash

SCRIPT_DIR=$(dirname "$(realpath "$0")")
RUN_SCRIPT="$SCRIPT_DIR/../test/cmake/azure_iot/run.sh"

. ./func_build.sh
