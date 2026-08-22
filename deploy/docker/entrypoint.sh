#!/usr/bin/env sh
set -eu

if [ "${1:-}" = "healthcheck" ]; then
  health_address=${CONTEXTDB_HEALTH_ADDRESS:-}
  if [ -z "$health_address" ]; then
    listen_address=${CONTEXTDB_HTTP_LISTEN:-0.0.0.0:7733}
    case "$listen_address" in
      *:*) health_port=${listen_address##*:} ;;
      *)
        echo "CONTEXTDB_HTTP_LISTEN must include a port for the health probe" >&2
        exit 64
        ;;
    esac
    case "$health_port" in
      ''|*[!0-9]*)
        echo "CONTEXTDB_HTTP_LISTEN has an invalid health probe port" >&2
        exit 64
        ;;
    esac
    if [ "$health_port" -lt 1 ] || [ "$health_port" -gt 65535 ]; then
      echo "CONTEXTDB_HTTP_LISTEN health probe port is outside 1..65535" >&2
      exit 64
    fi
    health_address="127.0.0.1:$health_port"
  fi
  exec contextdb --json probe --address "$health_address"
fi

state_path=${CONTEXTDB_STATE_PATH:-/var/lib/contextdb/contextdb.ctxb}
state_head_path=${CONTEXTDB_STATE_HEAD_FILE:-}

case "$state_path" in
  /*) ;;
  *)
    echo "CONTEXTDB_STATE_PATH must be absolute" >&2
    exit 64
    ;;
esac

case "$state_head_path" in
  /*) ;;
  "")
    echo "CONTEXTDB_STATE_HEAD_FILE is required" >&2
    exit 78
    ;;
  *)
    echo "CONTEXTDB_STATE_HEAD_FILE must be absolute" >&2
    exit 78
    ;;
esac

state_directory=$(dirname -- "$state_path")
authority_directory=$(dirname -- "$state_head_path")

if [ ! -d "$state_directory" ]; then
  echo "CONTEXTDB_STATE_PATH parent must exist" >&2
  exit 78
fi

if [ ! -d "$authority_directory" ] || [ ! -w "$authority_directory" ]; then
  echo "CONTEXTDB_STATE_HEAD_FILE parent must be a writable protected directory" >&2
  exit 78
fi

canonical_state_directory=$(CDPATH= cd -- "$state_directory" && pwd -P)
canonical_authority_directory=$(CDPATH= cd -- "$authority_directory" && pwd -P)
case "$canonical_authority_directory/" in
  "$canonical_state_directory/"*)
  echo "CONTEXTDB_STATE_HEAD_FILE must be outside the archive directory" >&2
  exit 78
  ;;
esac

authority_uid=$(stat -c '%u' -- "$canonical_authority_directory")
authority_mode=$(stat -c '%a' -- "$canonical_authority_directory")
if [ "$authority_uid" != "$(id -u)" ] || case "$authority_mode" in *00) false;; *) true;; esac; then
  echo "state-head authority directory must be owned by the container user with no group/other permissions" >&2
  exit 78
fi

if [ -n "${CONTEXTDB_TOKEN_KEY_HEX:-}" ] && [ -n "${CONTEXTDB_TOKEN_KEY_FILE:-}" ]; then
  echo "set exactly one of CONTEXTDB_TOKEN_KEY_HEX or CONTEXTDB_TOKEN_KEY_FILE" >&2
  exit 78
fi

if [ -z "${CONTEXTDB_TOKEN_KEY_HEX:-}" ] && [ -z "${CONTEXTDB_TOKEN_KEY_FILE:-}" ]; then
  echo "an external ContextDB token key is required" >&2
  exit 78
fi

if [ -n "${CONTEXTDB_TOKEN_KEY_FILE:-}" ]; then
  case "$CONTEXTDB_TOKEN_KEY_FILE" in
    /*) ;;
    *)
      echo "CONTEXTDB_TOKEN_KEY_FILE must be absolute" >&2
      exit 78
      ;;
  esac
  if [ ! -r "$CONTEXTDB_TOKEN_KEY_FILE" ]; then
    echo "CONTEXTDB_TOKEN_KEY_FILE is not readable" >&2
    exit 78
  fi
  if [ -L "$CONTEXTDB_TOKEN_KEY_FILE" ] || [ ! -f "$CONTEXTDB_TOKEN_KEY_FILE" ]; then
    echo "CONTEXTDB_TOKEN_KEY_FILE must be a regular non-symlink file" >&2
    exit 78
  fi
  key_directory=$(CDPATH= cd -- "$(dirname -- "$CONTEXTDB_TOKEN_KEY_FILE")" && pwd -P)
  case "$key_directory/" in
    "$canonical_state_directory/"*)
    echo "CONTEXTDB_TOKEN_KEY_FILE must be outside the archive directory" >&2
    exit 78
    ;;
  esac
  key_uid=$(stat -c '%u' -- "$CONTEXTDB_TOKEN_KEY_FILE")
  key_links=$(stat -c '%h' -- "$CONTEXTDB_TOKEN_KEY_FILE")
  key_mode=$(stat -c '%a' -- "$CONTEXTDB_TOKEN_KEY_FILE")
  if [ "$key_uid" != "$(id -u)" ]; then
    echo "CONTEXTDB_TOKEN_KEY_FILE must be owned by the container user" >&2
    exit 78
  fi
  if [ "$key_links" != "1" ] || case "$key_mode" in *00) false;; *) true;; esac; then
    echo "CONTEXTDB_TOKEN_KEY_FILE must have one link and no group/other permissions" >&2
    exit 78
  fi
fi

if [ "$#" -gt 0 ]; then
  exec "$@"
fi

if [ -z "${CONTEXTDB_GATEWAY_ID:-}" ]; then
  echo "CONTEXTDB_GATEWAY_ID is required for the network daemon" >&2
  exit 78
fi

if [ -n "${CONTEXTDB_GATEWAY_KEY_HEX:-}" ] && [ -n "${CONTEXTDB_GATEWAY_KEY_FILE:-}" ]; then
  echo "set exactly one of CONTEXTDB_GATEWAY_KEY_HEX or CONTEXTDB_GATEWAY_KEY_FILE" >&2
  exit 78
fi

if [ -z "${CONTEXTDB_GATEWAY_KEY_HEX:-}" ] && [ -z "${CONTEXTDB_GATEWAY_KEY_FILE:-}" ]; then
  echo "an external gateway attestation key is required" >&2
  exit 78
fi

if [ -n "${CONTEXTDB_GATEWAY_KEY_FILE:-}" ]; then
  case "$CONTEXTDB_GATEWAY_KEY_FILE" in
    /*) ;;
    *)
      echo "CONTEXTDB_GATEWAY_KEY_FILE must be absolute" >&2
      exit 78
      ;;
  esac
  if [ ! -r "$CONTEXTDB_GATEWAY_KEY_FILE" ] || [ -L "$CONTEXTDB_GATEWAY_KEY_FILE" ] || [ ! -f "$CONTEXTDB_GATEWAY_KEY_FILE" ]; then
    echo "CONTEXTDB_GATEWAY_KEY_FILE must be a readable regular non-symlink file" >&2
    exit 78
  fi
  gateway_key_directory=$(CDPATH= cd -- "$(dirname -- "$CONTEXTDB_GATEWAY_KEY_FILE")" && pwd -P)
  case "$gateway_key_directory/" in
    "$canonical_state_directory/"*)
    echo "CONTEXTDB_GATEWAY_KEY_FILE must be outside the archive directory" >&2
    exit 78
    ;;
  esac
  gateway_key_uid=$(stat -c '%u' -- "$CONTEXTDB_GATEWAY_KEY_FILE")
  gateway_key_links=$(stat -c '%h' -- "$CONTEXTDB_GATEWAY_KEY_FILE")
  gateway_key_mode=$(stat -c '%a' -- "$CONTEXTDB_GATEWAY_KEY_FILE")
  gateway_key_size=$(wc -c < "$CONTEXTDB_GATEWAY_KEY_FILE")
  if [ "$gateway_key_uid" != "$(id -u)" ] || [ "$gateway_key_links" != "1" ]; then
    echo "CONTEXTDB_GATEWAY_KEY_FILE must be owned by the container user with one link" >&2
    exit 78
  fi
  if case "$gateway_key_mode" in *00) false;; *) true;; esac || [ "$gateway_key_size" -gt 66 ]; then
    echo "CONTEXTDB_GATEWAY_KEY_FILE must be private and at most 66 bytes" >&2
    exit 78
  fi
  gateway_key_value=$(cat -- "$CONTEXTDB_GATEWAY_KEY_FILE")
  case "$gateway_key_value" in
    *[!0-9A-Fa-f]*|'')
      echo "CONTEXTDB_GATEWAY_KEY_FILE must contain exactly 64 hexadecimal characters" >&2
      exit 78
      ;;
  esac
  if [ "${#gateway_key_value}" -ne 64 ]; then
    echo "CONTEXTDB_GATEWAY_KEY_FILE must contain exactly 64 hexadecimal characters" >&2
    exit 78
  fi
  case "$gateway_key_size" in
    64) ;;
    65)
      [ "$(tail -c 1 -- "$CONTEXTDB_GATEWAY_KEY_FILE" | od -An -t x1 | tr -d ' ')" = "0a" ] || exit 78
      ;;
    66)
      [ "$(tail -c 2 -- "$CONTEXTDB_GATEWAY_KEY_FILE" | od -An -t x1 | tr -d ' ')" = "0d0a" ] || exit 78
      ;;
    *)
      echo "CONTEXTDB_GATEWAY_KEY_FILE has invalid framing" >&2
      exit 78
      ;;
  esac
  CONTEXTDB_GATEWAY_KEY_HEX=$gateway_key_value
  unset gateway_key_value
  export CONTEXTDB_GATEWAY_KEY_HEX
  unset CONTEXTDB_GATEWAY_KEY_FILE
fi

if [ ! -f "$state_path" ]; then
  contextdb --json init "$state_path"
fi

exec contextdb serve "$state_path" \
  --http-listen "${CONTEXTDB_HTTP_LISTEN:-0.0.0.0:7733}" \
  --grpc-listen "${CONTEXTDB_GRPC_LISTEN:-0.0.0.0:7734}"
