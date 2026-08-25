#!/bin/sh
set -eu

if [ "$(uname -s)" != "FreeBSD" ]; then
    echo "gwr-docket-bootstrap static build requires native FreeBSD" >&2
    exit 69
fi
if [ "$(uname -m)" != "amd64" ]; then
    echo "gwr-docket-bootstrap qualification profile requires amd64" >&2
    exit 69
fi

if [ "${GWR_BOOTSTRAP_FAULT_INJECTION:-0}" = "1" ]; then
    RUSTFLAGS="${RUSTFLAGS:-} -C target-feature=+crt-static" \
        cargo build --locked --release -p gwr-docket-bootstrap \
        --features fault-injection
else
    RUSTFLAGS="${RUSTFLAGS:-} -C target-feature=+crt-static" \
        cargo build --locked --release -p gwr-docket-bootstrap
fi
binary=target/release/gwr-docket-bootstrap
file "$binary"
if ldd "$binary" >/dev/null 2>&1; then
    echo "gwr-docket-bootstrap is dynamically linked" >&2
    exit 1
fi
sha256 "$binary"
