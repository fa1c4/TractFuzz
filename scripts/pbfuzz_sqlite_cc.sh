#!/usr/bin/env bash
# The author Magma sqlite3 build links a C++ file-input proxy through its C compiler.
set -euo pipefail
for argument in "$@"; do
    case "$argument" in
        -c|-E|-S) exec clang-15 "$@" ;;
    esac
done
exec clang-15 "$@" -lstdc++
