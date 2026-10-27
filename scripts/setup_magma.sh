#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
destination="${repo_root}/magma"
revision="${MAGMA_REVISION:-cec1fec38fdc510c2cb8e6ae690e738b1042cb8d}"
remote="https://github.com/vusec/magma-directed.git"
created=0

if [[ ! -e "$destination" ]]; then
    git -c http.version=HTTP/1.1 clone --depth 1 --filter=blob:none \
        --single-branch --branch directed --no-checkout "$remote" "$destination"
    created=1
fi
if [[ ! -d "$destination/.git" ]]; then
    echo "Refusing to replace an existing non-Git directory: $destination" >&2
    exit 1
fi
actual="$(git -C "$destination" rev-parse HEAD)"
if [[ "$actual" != "$revision" && "$created" == 1 ]]; then
    git -C "$destination" -c http.version=HTTP/1.1 fetch --depth 1 \
        --filter=blob:none origin "$revision"
    git -C "$destination" update-ref refs/heads/directed "$revision"
    actual="$(git -C "$destination" rev-parse HEAD)"
fi
if [[ "$actual" != "$revision" ]]; then
    echo "Magma checkout is $actual; expected $revision. Refusing to change it." >&2
    exit 1
fi
if [[ -n "$(git -C "$destination" status --porcelain --untracked-files=no)" ]]; then
    echo "Magma has local tracked changes; refusing to overwrite them." >&2
    exit 1
fi
git -C "$destination" config http.version HTTP/1.1

# Fetch source and patches first. Fetch each corpus separately so interrupted
# transfers can be resumed without repeating a large archive download.
git -C "$destination" sparse-checkout init --no-cone
git -C "$destination" sparse-checkout set \
    '/README.md' '/.gitmodules' '/docs/' '/magma/' '/tools/' \
    '/docker/' '/fuzzers/libaflgo_aflgo/' '/targets/' \
    '!/targets/*/corpus/'
git -C "$destination" checkout -f "$revision"

if [[ "${MAGMA_INCLUDE_CORPORA:-1}" == 1 ]]; then
    for project in libpng libsndfile libtiff libxml2 lua openssl php poppler sqlite3; do
        completed=0
        for attempt in 1 2 3 4 5; do
            if git -C "$destination" sparse-checkout add "/targets/$project/corpus/"; then
                completed=1
                break
            fi
            if [[ "$project" == poppler && "$attempt" == 2 ]]; then
                # This pinned Poppler PDF is a shared blob in three corpora.
                # Some partial-clone servers fail repeatedly on that one
                # object. Fetch it from the same pinned revision and verify
                # its Git object ID before retrying the sparse checkout.
                blob=27551c2c6c7eca55cfc7f0dd8c74ba9943beda8f
                if ! git -C "$destination" cat-file -e "$blob" 2>/dev/null; then
                    temporary="$(mktemp)"
                    if curl -fsSL --retry 3 \
                        "https://raw.githubusercontent.com/vusec/magma-directed/$revision/targets/poppler/corpus/pdf_fuzzer/1-criticalnotes.pdf" \
                        -o "$temporary"; then
                        actual_blob="$(git -C "$destination" hash-object "$temporary")"
                        if [[ "$actual_blob" == "$blob" ]]; then
                            git -C "$destination" hash-object -w "$temporary" >/dev/null
                        fi
                    fi
                    rm -f "$temporary"
                fi
            fi
            echo "Retrying $project corpus download ($attempt/5)" >&2
            sleep "$((attempt * 2))"
        done
        if [[ "$completed" != 1 ]]; then
            echo "Could not fetch $project corpus" >&2
            exit 1
        fi
    done
fi
echo "Installed Magma-directed $revision at $destination"
