#!/usr/bin/env bash

set -euo pipefail

main() {
  mkdir -p .dummy/utils/src
  mkdir -p .dummy/proxy/src
  cp Cargo.toml Cargo.lock .dummy/
  cp proxy/Cargo.toml .dummy/proxy/src
  cp utils/Cargo.toml .dummy/utils/src
  sed -i 's/^version = "[^"]*"$/version = "1.0.0"/' .dummy/proxy/src/Cargo.toml
  sed -i 's/^version = "[^"]*"$/version = "0.3.0"/' .dummy/utils/src/Cargo.toml
  touch .dummy/proxy/src/main.rs
  touch .dummy/utils/src/lib.rs
}

main "$@"
