#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
revision=86d11b35c2d8885bd35ab7b9b8d627a91954d80d
sha256=bee9502244e5fdf696ee47f253e92ef3b81a2f2c3404a7d62965ec1a6f4726fe
archive="$root/results/idfuzz/source/IDFuzz-$revision.tar.gz"
mkdir -p "$(dirname "$archive")"
if [[ ! -s "$archive" ]]; then
    curl -fsSL --retry 4 "https://codeload.github.com/vul337/IDFuzz/tar.gz/$revision" -o "$archive.tmp"
    mv "$archive.tmp" "$archive"
fi
printf '%s  %s\n' "$sha256" "$archive" | sha256sum -c -
mkdir -p "$root/results/idfuzz/source/author"
tar -xzf "$archive" -C "$root/results/idfuzz/source/author" --strip-components=1
printf '%s\n' "$root/results/idfuzz/source/author"
