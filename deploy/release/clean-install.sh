#!/usr/bin/env sh
set -eu

# The verifier, not this wrapper, provisions child-only token-key input and a
# fresh platform state-head authority per destination. Caller CONTEXTDB_*
# custody variables are neither forwarded to probes nor serialized in reports.
usage() {
  echo "usage: $0 BUNDLE_ROOT [MANIFEST] [PROFILE] [REPORT] [KEY_ID=PUBLIC_KEY.pem]" >&2
  exit 64
}

[ "$#" -ge 1 ] || usage

bundle_root=$1
manifest=${2:-release/artifact-manifest.json}
profile=${3:-release}
report=${4:-}
trusted_key=${5:-}

[ "$#" -le 5 ] || usage

case "$profile" in
  contract|release) ;;
  *) usage ;;
esac

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
repo_root=$(CDPATH= cd -- "$script_dir/../.." && pwd -P)
verifier=$repo_root/tools/contextdb-release/contextdb_release.py

[ -f "$verifier" ] || {
  echo "release verifier not found: $verifier" >&2
  exit 66
}

if [ -n "$trusted_key" ]; then
  case "$trusted_key" in
    *=*) ;;
    *) usage ;;
  esac
  if [ -n "$report" ]; then
    exec python3 "$verifier" clean-install \
      --bundle-root "$bundle_root" \
      --manifest "$manifest" \
      --profile "$profile" \
      --report "$report" \
      --trusted-key "$trusted_key"
  fi
  exec python3 "$verifier" clean-install \
    --bundle-root "$bundle_root" \
    --manifest "$manifest" \
    --profile "$profile" \
    --trusted-key "$trusted_key"
fi

if [ -n "$report" ]; then
  exec python3 "$verifier" clean-install \
    --bundle-root "$bundle_root" \
    --manifest "$manifest" \
    --profile "$profile" \
    --report "$report"
fi

exec python3 "$verifier" clean-install \
  --bundle-root "$bundle_root" \
  --manifest "$manifest" \
  --profile "$profile"
