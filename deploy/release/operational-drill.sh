#!/usr/bin/env sh
set -eu

# The Python runner creates child-only custody inputs. Caller CONTEXTDB_*
# variables are neither forwarded to the old/new binaries nor serialized.
usage() {
  echo "usage: $0 OLD_BUNDLE NEW_BUNDLE PLAN [PROFILE] [REPORT] [KEY_ID=PUBLIC_KEY.pem]" >&2
  exit 64
}

[ "$#" -ge 3 ] || usage
[ "$#" -le 6 ] || usage

old_bundle=$1
new_bundle=$2
plan=$3
profile=${4:-release}
report=${5:-}
trusted_key=${6:-}

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

set -- python3 "$verifier" operational-drill \
  --old-bundle-root "$old_bundle" \
  --new-bundle-root "$new_bundle" \
  --plan "$plan" \
  --profile "$profile"

if [ -n "$report" ]; then
  set -- "$@" --report "$report"
fi
if [ -n "$trusted_key" ]; then
  case "$trusted_key" in
    *=*) ;;
    *) usage ;;
  esac
  set -- "$@" --trusted-key "$trusted_key"
fi

exec "$@"
