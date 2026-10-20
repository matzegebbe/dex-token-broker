#!/usr/bin/env bash
set -euo pipefail

# Docker and Go module manifests are maintained by Dependabot. Keep CI inputs
# derived from those manifests instead of repeating untracked version pins.
go_version=$(awk '$1 == "FROM" && $3 ~ /^golang:/ && $4 == "AS" && $5 == "build" { sub(/^golang:/, "", $3); print $3 }' Dockerfile)
trivy_version=$(awk '$1 == "image:" && $2 ~ /^aquasec\/trivy:/ { sub(/^aquasec\/trivy:/, "", $2); print "v" $2 }' tools/compose.yml)
goreleaser_version=$(awk '$1 == "image:" && $2 ~ /^goreleaser\/goreleaser:/ { sub(/^goreleaser\/goreleaser:/, "", $2); print $2 }' tools/compose.yml)

[[ "$go_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo 'Expected one pinned Go build image in Dockerfile' >&2; exit 1; }
for version in "$trivy_version" "$goreleaser_version"; do
  [[ "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo 'Expected pinned tool image versions in tools/compose.yml' >&2; exit 1; }
done

printf 'go=%s\ntrivy=%s\ngoreleaser=%s\n' "$go_version" "$trivy_version" "$goreleaser_version"
