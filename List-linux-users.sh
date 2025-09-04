#!/bin/sh
set -eu

ScriptName="List-Linux-Users"
LogPath="/tmp/${ScriptName}-script.log"
ARLog="/var/ossec/logs/active-responses.log"
LogMaxKB=100
LogKeep=5
HostName="$(hostname)"
runStart=$(date +%s)
MIN_UID="${Arg1:-1000}"

WriteLog() {
  Message="$1"; Level="${2:-INFO}"
  ts="$(date '+%Y-%m-%d %H:%M:%S')"
  line="[$ts][$Level] $Message"
  case "$Level" in
    ERROR) printf '\033[31m%s\033[0m\n' "$line" ;;
    WARN)  printf '\033[33m%s\033[0m\n' "$line" ;;
    DEBUG) [ "${VERBOSE:-0}" -eq 1 ] && printf '%s\n' "$line" ;;
    *)     printf '%s\n' "$line" ;;
  esac
  printf '%s\n' "$line" >> "$LogPath"
}

RotateLog() {
  [ -f "$LogPath" ] || return 0
  size_kb=$(du -k "$LogPath" | awk '{print $1}')
  [ "$size_kb" -le "$LogMaxKB" ] && return 0
  i=$((LogKeep-1))
  while [ $i -ge 0 ]; do
    [ -f "$LogPath.$i" ] && mv -f "$LogPath.$i" "$LogPath.$((i+1))"
    i=$((i-1))
  done
  mv -f "$LogPath" "$LogPath.1"
}

escape_json() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }

shadow_status() {
  user="$1"
  entry=$(grep "^$user:" /etc/shadow 2>/dev/null || true)
  if [ -z "$entry" ]; then printf 'true|false'; return; fi
  pw_field=$(printf '%s' "$entry" | cut -d: -f2)
  expire_days=$(printf '%s' "$entry" | cut -d: -f8)
  today=$(($(date +%s)/86400))
  required=true
  expired=false
  [ "$pw_field" = "!" ] || [ "$pw_field" = "*" ] && required=false
  [ -n "$expire_days" ] && [ "$expire_days" -gt 0 ] && [ "$expire_days" -lt "$today" ] && expired=true
  printf '%s|%s' "$required" "$expired"
}

groups_json_for_user() {
  user="$1"
  g=$(id -nG "$user" 2>/dev/null || true)
  if [ -z "$g" ]; then printf '[]'; return; fi
  set -- $g
  out='['
  first=1
  for grp in "$@"; do
    esc=$(escape_json "$grp")
    if [ $first -eq 1 ]; then out="$out\"$esc\""; first=0
    else out="$out,\"$esc\""
    fi
  done
  printf '%s]\n' "$out"
}

lastlogon_for_user() {
  user="$1"
  if command -v lastlog >/dev/null 2>&1; then
    ll=$(lastlog "$user" 2>/dev/null | tail -n +2 | head -n1 || true)
    if printf '%s' "$ll" | grep -qi 'Never logged in'; then printf 'Never logged in'; else printf '%s' "$ll"; fi
  else
    printf 'Unavailable'
  fi
}

RotateLog
WriteLog "=== SCRIPT START : $ScriptName (host=$HostName) ==="

tmpfile="$(mktemp)"
ts_iso="$(date --iso-8601=seconds 2>/dev/null || date '+%Y-%m-%dT%H:%M:%S%z')"

# One NDJSON line per user (root + >= MIN_UID)
getent passwd | while IFS=: read -r username x uid gid gecos home shell; do
  [ -n "${username:-}" ] || continue
  case "$username" in daemon|bin|sys|sync|games|man|lp|mail|news) continue ;; esac
  case "$uid" in '' ) continue ;; esac
  if [ "$uid" -ne 0 ] && [ "$uid" -lt "$MIN_UID" ]; then continue; fi
  desc="$(escape_json "$gecos")"
  groups_json="$(groups_json_for_user "$username")"
  lastlogon_raw="$(lastlogon_for_user "$username")"
  lastlogon="$(escape_json "$lastlogon_raw")"
  sw="$(shadow_status "$username")"
  pw_required="$(printf '%s' "$sw" | cut -d'|' -f1)"
  pw_expired="$(printf '%s' "$sw" | cut -d'|' -f2)"
  printf '{"timestamp":"%s","host":"%s","action":"list_linux_users","copilot_action":true,"username":"%s","uid":%s,"gid":%s,"description":"%s","home":"%s","shell":"%s","groups":%s,"lastlogon":"%s","password_required":%s,"password_expired":%s}\n' \
    "$ts_iso" "$HostName" "$(escape_json "$username")" "$uid" "$gid" "$desc" "$(escape_json "$home")" "$(escape_json "$shell")" \
    "$groups_json" "$lastlogon" "$pw_required" "$pw_expired" >> "$tmpfile"
done

# Do NOT pre-clear ARLog. Overwrite with atomic move; fallback to .new if blocked.
AR_DIR="$(dirname "$ARLog")"
[ -d "$AR_DIR" ] || WriteLog "Directory missing: $AR_DIR (will attempt write anyway)" WARN

if mv -f "$tmpfile" "$ARLog"; then
  WriteLog "Wrote NDJSON (one line per user) to $ARLog" INFO
else
  WriteLog "Primary write FAILED to $ARLog" WARN
  if mv -f "$tmpfile" "$ARLog.new"; then
    WriteLog "Wrote NDJSON to $ARLog.new (fallback)" WARN
  else
    WriteLog "Failed to write both $ARLog and $ARLog.new" ERROR
    keep="/tmp/active-responses.$$.ndjson"
    cp -f "$tmpfile" "$keep" 2>/dev/null || true
    WriteLog "Saved fallback copy at $keep" WARN
    rm -f "$tmpfile" 2>/dev/null || true
    exit 1
  fi
fi

# Verify where data is
for p in "$ARLog" "$ARLog.new"; do
  if [ -f "$p" ]; then
    sz=$(wc -c < "$p" 2>/dev/null || echo 0)
    ino=$(ls -li "$p" 2>/dev/null | awk '{print $1}')
    head1=$(head -n1 "$p" 2>/dev/null || true)
    WriteLog "VERIFY: path=$p inode=$ino size=${sz}B first_line=${head1:-<empty>}" INFO
  fi
done

dur=$(( $(date +%s) - runStart ))
WriteLog "=== SCRIPT END : ${dur}s ==="
