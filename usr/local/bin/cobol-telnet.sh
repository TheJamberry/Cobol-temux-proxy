#!/usr/bin/env bash
set -euo pipefail

COBOL_HOST="${COBOL_HOST:-10.0.0.25}"
COBOL_PORT="${COBOL_PORT:-23}"
TERM_TYPE="${TERM_TYPE:-vt100}"
SRC_IP="${SRC_IP:-}"

export TERM="$TERM_TYPE"
stty sane || true

has_telnet_bind() { telnet -h 2>&1 | grep -q -- " -b "; }
has_socat() { command -v socat >/dev/null 2>&1; }

if has_socat; then
  if [[ -n "$SRC_IP" ]]; then
    exec socat -,raw,echo=0 TCP4:"$COBOL_HOST":"$COBOL_PORT",sourceip="$SRC_IP"
  else
    exec socat -,raw,echo=0 TCP4:"$COBOL_HOST":"$COBOL_PORT"
  fi
else
  if [[ -n "$SRC_IP" ]] && has_telnet_bind; then
    exec telnet -8 -E -K -b "$SRC_IP" "$COBOL_HOST" "$COBOL_PORT"
  else
    exec telnet -8 -E -K "$COBOL_HOST" "$COBOL_PORT"
  fi
fi
