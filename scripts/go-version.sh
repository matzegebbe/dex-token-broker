#!/usr/bin/env bash
set -euo pipefail

# Dependabot maintains this image pin. Use it for CI and release binaries too.
go_version=$(awk '$1 == "FROM" && $3 ~ /^golang:/ && $4 == "AS" && $5 == "build" { sub(/^golang:/, "", $3); print $3 }' Dockerfile)

if [[ ! "$go_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo 'Expected one pinned Go build image in Dockerfile' >&2
  exit 1
fi

printf 'go=%s\n' "$go_version"
