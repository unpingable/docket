# REGISTRY-SEED002 / BUILD002 input correction

Prepared source contract only; no seed producer, Cargo build, container or VM
launch is authorized by this file. REGISTRY-SEED001 remains refused and retained.

The seed producer now creates the receipt with O_CREAT|O_EXCL|O_NOFOLLOW and
reserves the seed directory with exclusive mkdir. lstat absence gates refuse
both ordinary and dangling names; physical parent checks refuse symlinked
parents. An interrupted admission retains the output and empty/partial receipt;
neither is reused. Finalization changes regular files to 0444 and directories
including the root to 0555 **before** the V2 tree digest and canonical receipt.
No post-receipt chmod of the seed is permitted. The V2 transcript domain is
`operator-beta-cargo-registry-seed-v2`; ordered records include root, directories
and files, type, path length/path, mode, content length/content. Thus directory
mode changes as well as file mode/content changes affect the binding.

The source cache and campaign parent directories are under exclusive campaign
custody for this workflow. lstat/descriptor checks do not establish confinement
against an uncoordinated same-UID writer replacing ancestors or changing and
restoring content between observations. No atomic whole-tree snapshot is
claimed. The bounded local source input remains the existing cache: index
100,000 files / 512 MiB; archives 64 MiB each / 1 GiB aggregate. Counts bound
accepted content, not every physical/runtime read or peak interpreter memory.

The builder replaces only AG's directory-source vendor option with three
required explicit inputs: `--ag-registry-seed`, `--ag-registry-receipt`, and
`--ag-registry-receipt-sha256`. The Docket vendor input remains unchanged.
Verification binds canonical receipt bytes, exact AG lock/source/target,
archive lock partition and checksums, index inventory, read-only modes, and the
post-finalization V2 tree. The receipt SHA is an independent-review input, not
learned implicitly from whichever file currently occupies the receipt path.
BUILD002 cannot be frozen as an executable occurrence until SEED002's actual
receipt and seed are independently accepted and their exact hashes supplied.

Each build case copies the seed to its own exclusive `a/ag-cargo` or
`b/ag-cargo` directory, verifies copied content/modes against the read-only
seed, then makes **only that derivative** writable. Copying creates independent
files, not hard links. The original seed is additionally mounted read-only at
`/ag-registry-seed`, the derivative read-write at `/cargo-home`; source is
read-only and target state distinct per case. AG config is net.offline=true,
without directory-source replacement. Cargo runs locked/offline with Docker
`--network none --pull never` and the preexisting exact pinned image. A missing
required dependency fails offline; unavailable Windows-only identities are not
presumed dispensable without a separate offline Linux derivation/build result.
No fallback to vendor, mutable shared Cargo home, network or image retrieval is
implemented. The seed is reverified before a successful build receipt.

The fixture receipt schema is V2 (the historical receipt filename remains
`fixture-build-receipt.v1.json` for now); its AG input entry explicitly records
registry seed/receipt facts and its qualification entry binds both builder and
registry helper source hashes. This is BUILD002 input integration, not a claim
that historical VM/checker packages accept the changed fixture receipt. Package
qualification and any checker/VM adaptation require their own reviewed gates.

Tiny local deterministic tests cover post-mode binding, file/directory mode
tamper, content/hash tamper, dangling seed/receipt/Cargo/output paths, exclusive
substitution refusal, interruption retention, independent writable copies and
the actual build_case command/config wiring with external execution mocked.
Four Rust gates and real Cargo/container builds are intentionally not run in
this source-only correction scope. Owner storage reconciliation and durable
execution/recovery records are prerequisites for any later seed or build run.
