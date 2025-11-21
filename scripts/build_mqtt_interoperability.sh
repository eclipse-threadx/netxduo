#! /bin/bash

SCRIPT_DIR=$(dirname "$(realpath "$0")")
RUN_SCRIPT="$SCRIPT_DIR/../test/cmake/mqtt_interoperability/run.sh"

. ./func_build.sh
