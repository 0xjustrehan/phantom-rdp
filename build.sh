#!/usr/bin/env bash
set -e

echo "[*] Building phantom-rdp release binary..."
cargo build --release

echo "[+] Build complete: target/release/phantom-rdp"
ls -lh target/release/phantom-rdp
