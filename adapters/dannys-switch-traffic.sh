#!/usr/bin/env bash
set -euo pipefail
umask 077

APP_ROOT="${APP_ROOT:-/home/bryan/apps/dannys}"
HELPER="${SLIPSTREAM_CADDY_HELPER:-/usr/local/sbin/slipstream-caddy}"
TARGET_SLOT="${1:-}"

case "$TARGET_SLOT" in
  blue) TARGET_PORT=4120 ;;
  green) TARGET_PORT=4121 ;;
  *) echo "usage: $0 blue|green" >&2; exit 64 ;;
esac

run_helper() {
  if [[ $(id -u) -eq 0 ]]; then
    "$HELPER" "$@"
  else
    sudo -n "$HELPER" "$@"
  fi
}

marker_tmp=$(mktemp "$APP_ROOT/shared/.active_slot.XXXXXX")
printf '%s\n' "$TARGET_SLOT" >"$marker_tmp"
transaction_id=""
marker_updated=false

restore_uncommitted_route() {
  local status=$?
  trap - EXIT
  rm -f "$marker_tmp"

  if [[ -n "$transaction_id" && "$marker_updated" != true ]]; then
    echo "Dannys marker update failed; restoring transaction $transaction_id" >&2
    run_helper restore dannys "$transaction_id" >/dev/null || status=1
  fi

  exit "$status"
}
trap restore_uncommitted_route EXIT

transaction_id=$(run_helper switch dannys "$TARGET_SLOT")
mv "$marker_tmp" "$APP_ROOT/shared/active_slot"
marker_updated=true
trap - EXIT

echo "active slot: $TARGET_SLOT (port $TARGET_PORT, transaction $transaction_id)"
