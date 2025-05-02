#!/usr/bin/env bash

export DATA_DIRECTORY="$(pwd)/test_syncserver"
export USE_VALKEY_CACHE=false

mkdir -p "$DATA_DIRECTORY"

pytest "$@"
