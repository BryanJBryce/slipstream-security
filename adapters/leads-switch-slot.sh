#!/usr/bin/env bash
set -euo pipefail
umask 077

APP_ROOT="${APP_ROOT:-/home/bryan/apps/leads}"
HELPER="${SLIPSTREAM_CADDY_HELPER:-/usr/local/sbin/slipstream-caddy}"
slot="${1:-}"

case "$slot" in
  red) port=4560; previous=green ;;
  green) port=4561; previous=red ;;
  *) echo "usage: $0 red|green" >&2; exit 64 ;;
esac

run_helper() {
  if [[ $(id -u) -eq 0 ]]; then
    "$HELPER" "$@"
  else
    sudo -n "$HELPER" "$@"
  fi
}

marker_tmp=$(mktemp "$APP_ROOT/shared/.active_slot.XXXXXX")
previous_tmp=$(mktemp "$APP_ROOT/shared/.previous_slot.XXXXXX")
printf '%s\n' "$slot" >"$marker_tmp"
printf '%s\n' "$previous" >"$previous_tmp"
transaction_id=""
marker_updated=false

restore_uncommitted_route() {
  local status=$?
  trap - EXIT
  rm -f "$marker_tmp" "$previous_tmp"

  if [[ -n "$transaction_id" && "$marker_updated" != true ]]; then
    echo "Leads marker update failed; restoring transaction $transaction_id" >&2
    run_helper restore leads "$transaction_id" >/dev/null || status=1
  fi

  exit "$status"
}
trap restore_uncommitted_route EXIT

transaction_id=$(run_helper switch leads "$slot")
mv "$marker_tmp" "$APP_ROOT/shared/active_slot"
marker_updated=true
mv "$previous_tmp" "$APP_ROOT/shared/previous_slot"
trap - EXIT

echo "active=$slot port=$port transaction=$transaction_id"
