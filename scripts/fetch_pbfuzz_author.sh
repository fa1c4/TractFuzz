#!/usr/bin/env bash
# Fetch and verify both author releases and the matching Magma fork.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source_dir="$root/results/pbfuzz/source"
mkdir -p "$source_dir"
fetch_git() {
    local url="$1" dest="$2" commit="$3"
    if [[ ! -d "$dest/.git" ]]; then
        git clone "$url" "$dest"
    fi
    if [[ "$(git -C "$dest" rev-parse HEAD)" != "$commit" ]]; then
        git -C "$dest" fetch --depth 1 origin "$commit"
        git -C "$dest" checkout --detach "$commit"
    fi
    [[ "$(git -C "$dest" rev-parse HEAD)" == "$commit" ]]
}
fetch_git https://github.com/sgzeng/pbfuzz.git "$source_dir/github" \
    70d0b96dce14961ca184e10d96838902bee9bae1
fetch_git https://github.com/R-Fuzz/magma.git "$source_dir/magma-author" \
    a6ec7b915a478306d0727f07848172500c3c4e11
archive="$source_dir/artifact.zip"
if [[ ! -s "$archive" ]]; then
    curl -fL --retry 3 'https://zenodo.org/records/20770567/files/artifact.zip?download=1' -o "$archive"
fi
printf '%s  %s\n' \
    76bccbead8b7c8bf5a5dde682eee7c7c0edbdca234dc4b0a5c95b15f85b0e6d0 \
    "$archive" | sha256sum -c -
python3 - "$archive" "$source_dir/zenodo" <<'PY'
import sys, zipfile
from pathlib import Path, PurePosixPath

archive, dest = Path(sys.argv[1]), Path(sys.argv[2])
with zipfile.ZipFile(archive) as z:
    for entry in z.infolist():
        name = PurePosixPath(entry.filename)
        if name.is_absolute() or ".." in name.parts or (entry.external_attr >> 16) & 0o170000 == 0o120000:
            raise SystemExit(f"unsafe artifact entry: {entry.filename}")
    dest.mkdir(parents=True, exist_ok=True)
    for entry in z.infolist():
        if entry.filename.startswith("__MACOSX/"):
            continue
        z.extract(entry, dest)
print("Verified and extracted Zenodo artifact v2")
PY
