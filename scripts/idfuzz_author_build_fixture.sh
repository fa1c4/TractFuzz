#!/usr/bin/env bash
set -euo pipefail
cd "$1"
"$CC" $CFLAGS fixture.c -o fixture
