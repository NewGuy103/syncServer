#!/usr/bin/env bash

export DATA_DIRECTORY="$(pwd)/test_syncserver"
mkdir -p "$DATA_DIRECTORY"

pytest "$@"
