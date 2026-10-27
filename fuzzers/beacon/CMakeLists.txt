set(BEACON_ENTRY_PRUNING TRUE)
corrosion_import_crate(MANIFEST_PATH Cargo.toml CRATE_TYPES staticlib CRATES
                       ${FUZZER})
