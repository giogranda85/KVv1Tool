#!/usr/bin/env bash
set -euo pipefail

# vault-kv1-dump.sh
# Recursively list and read all secrets from a KV v1 mount.
# Usage: ./vault-kv1-dump.sh <mount>
# Requires: curl, jq
#
# Output format (to stdout): JSON objects, one per secret:
# {"path":"secret/path","secret":{...}}
#
# SECURITY: avoid leaving VAULT_TOKEN in shell history or world-readable files.

MOUNT="${1:-}"
if [[ -z "$MOUNT" ]]; then
  echo "Usage: $0 <kv-v1-mount-name>" >&2
  exit 2
fi

# Check environment variables
if [[ -z "${VAULT_ADDR:-}" ]]; then
  echo "ERROR: VAULT_ADDR is not set. Please export VAULT_ADDR (e.g. https://vault.example.com:8200)" >&2
  exit 1
fi
if [[ -z "${VAULT_TOKEN:-}" ]]; then
  echo "ERROR: VAULT_TOKEN is not set. Please export VAULT_TOKEN (a valid token with read/list perms)" >&2
  exit 1
fi

# Check required tools
if ! command -v curl >/dev/null 2>&1; then
  echo "curl is required" >&2
  exit 2
fi
if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required" >&2
  exit 2
fi

# Helper to call Vault API and return stdout; exits on HTTP errors
api_get() {
  local url="$1"
  local resp
  resp="$(curl -sS -H "X-Vault-Token: ${VAULT_TOKEN}" --fail "$url")" || {
    echo "Error: HTTP request failed for $url" >&2
    return 1
  }
  printf '%s' "$resp"
}

# Detect whether mount is KV v1 or v2 (we expect v1)
# Sys mounts path includes a trailing slash in the key for mount name, ensure it matches
# Query sys/mounts/<mount> (Vault returns the mount config including type and options)
detect_kv_version() {
  local mount_path="$1"
  # ensure trailing slash in mount path as sys/mounts uses that form
  local sys_path="v1/sys/mounts/${mount_path}/"
  local url="${VAULT_ADDR}/${sys_path}"
  local out
  if out="$(api_get "$url")"; then
    # If this mount is kv and has "options": {"version":"2"} then it's kv v2
    local type
    type="$(printf '%s' "$out" | jq -r '.type // .data.type // empty')"
    local version
    version="$(printf '%s' "$out" | jq -r '.options.version // .data.options.version // empty')"
    # Some Vault versions present mount info under .data; be tolerant
    if [[ "$type" == "kv" && "$version" == "2" ]]; then
      echo "v2"
      return 0
    fi
  fi
  echo "v1"
}

kv_ver="$(detect_kv_version "$MOUNT")"
if [[ "$kv_ver" != "v1" ]]; then
  echo "Detected KV version: $kv_ver. This script is for KV v1 mounts only."
  echo "For KV v2 you must read from the /data/ and /metadata/ endpoints (different API paths)."
  exit 3
fi

# Normalized base URL for the mount (no trailing slash)
BASE_URL="${VAULT_ADDR%/}/v1/${MOUNT}"

# Recursively list keys under a prefix (prefix should NOT start with leading slash, but may be empty)
# We expect list endpoint: GET $BASE_URL/<prefix>?list=true
# Response: { "request_id": "...", "data": { "keys": ["foo","bar/"] } }
list_keys() {
  local prefix="$1"   # e.g. "", "app/", "app/dir/"
  local url
  if [[ -z "$prefix" ]]; then
    url="${BASE_URL}?list=true"
  else
    # Ensure prefix has no leading slash
    prefix="${prefix#/}"
    url="${BASE_URL}/${prefix}?list=true"
  fi

  local out
  out="$(curl -sS -H "X-Vault-Token: ${VAULT_TOKEN}" --fail "$url")" || {
    # If list returns 404 or non-listable, treat as empty
    return 0
  }

  # Extract keys array; if absent, nothing to do
  jq -r '.data.keys[]?' <<<"$out"
}

# Read a single key (leaf) and print JSON with path and secret content
read_secret() {
  local key_path="$1"   # e.g. "app/config"
  # build URL
  local url="${BASE_URL}/${key_path}"
  local out
  out="$(curl -sS -H "X-Vault-Token: ${VAULT_TOKEN}" --fail "$url")" || {
    echo "WARNING: failed to read $key_path" >&2
    return 1
  }

  # For kv v1, secret data live under .data
  # Output a JSON blob per secret: {"path":"<key_path>","secret":<data>}
  jq -c --arg p "$key_path" '{path:$p, secret:.data}' <<<"$out"
}

# Recursive traversal: for each key returned by list_keys:
# - if key ends with '/', it's a directory: recurse with prefix+key
# - otherwise it's a secret: read_secret prefix+key
traverse() {
  local prefix="$1"  # may be empty
  local keys=()

  # Read keys into an array safely
  while IFS= read -r line; do
    keys+=("$line")
  done < <(list_keys "$prefix")

  # If no keys, return
  if [[ "${#keys[@]}" -eq 0 ]]; then
    return 0
  fi

  local k
  for k in "${keys[@]}"; do
    if [[ "$k" == */ ]]; then
      traverse "${prefix}${k}"
    else
      read_secret "${prefix}${k}"
    fi
  done
}
# Start traversal at root
traverse ""

exit 0

