#!/bin/sh
set -eu

ScriptName="List-Linux-Users"
LogPath="/tmp/${ScriptName}-script.log"
ARLog="/var/ossec/logs/active-responses.log"
LogMaxKB=100
LogKeep=5
HostName="$(hostname)"
runStart=$(date +%s)

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

escape_json() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

shadow_status() {
  user="$1"
  entry=$(grep "^$user:" /etc/shadow 2>/dev/null || true)
  if [ -z "$entry" ]; then
    printf 'true|false'
    return
  fi
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
  if [ -z "$g" ]; then
    printf '[]'
  else
    printf '%s\n' "$g" | tr ' ' '\n' | sed 's/^/"/; s/$/"/' | paste -sd, - | sed 's/^/[/' | sed 's/$/]/'
  fi
}

lastlogon_for_user() {
  user="$1"
  ll=$(lastlog "$user" 2>/dev/null | tail -n +2 | head -n1 || true)
  if printf '%s' "$ll" | grep -qi 'Never logged in'; then
    printf 'Never logged in'
  else
    printf '%s' "$ll"
  fi
}

RotateLog
WriteLog "=== SCRIPT START : $ScriptName ==="

tmpfile="$(mktemp)"
ts_iso="$(date --iso-8601=seconds 2>/dev/null || date '+%Y-%m-%dT%H:%M:%S%z')"

getent passwd | awk -F: '($3==0)||($3>=1000){print $0}' | while IFS=: read -r username x uid gid gecos home shell; do
  [ -z "$username" ] && continue
  case "$username" in
    daemon|bin|sys|sync|games|man|lp|mail|news) continue ;;
  esac
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

AR_DIR="$(dirname "$ARLog")"
if ! install -d -m 0775 -o root -g ossec "$AR_DIR" 2>/dev/null; then
  WriteLog "Could not ensure dir $AR_DIR; continuing anyway" WARN
fi

if mv -f "$tmpfile" "$ARLog" 2>/dev/null; then
  WriteLog "Wrote NDJSON (one line per user) to $ARLog" INFO
else
  if mv -f "$tmpfile" "$ARLog.new" 2>/dev/null; then
    WriteLog "Primary path failed (locked/perm?). Wrote to $ARLog.new" WARN
  else
    WriteLog "Failed to write both $ARLog and $ARLog.new" ERROR
    rm -f "$tmpfile" 2>/dev/null || true
    exit 1
  fi
fi

dur=$(( $(date +%s) - runStart ))
WriteLog "=== SCRIPT END : ${dur}s ==="
