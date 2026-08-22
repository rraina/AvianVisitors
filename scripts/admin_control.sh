#!/usr/bin/env bash
# Root-owned control plane for the small set of privileged admin actions used
# by the AvianVisitors web interface. The caddy user may invoke this installed
# copy through sudo, but every action and argument is validated here.

set -euo pipefail
IFS=$'\n\t'
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 077

CONTROL_VERSION=1

json_escape() {
  local value=${1-}
  value=${value//\\/\\\\}
  value=${value//\"/\\\"}
  value=${value//$'\n'/\\n}
  value=${value//$'\r'/\\r}
  value=${value//$'\t'/\\t}
  printf '%s' "$value"
}

fail() {
  local message=${1:-admin control failed}
  printf '{"ok":false,"error":"%s"}\n' "$(json_escape "$message")"
  exit 1
}

[ "${EUID:-$(id -u)}" -eq 0 ] || fail "admin control must run as root"

conf_value() {
  local file=$1 key=$2
  awk -v wanted="$key" '
    $0 ~ "^[[:space:]]*" wanted "[[:space:]]*=" {
      value=$0
      sub(/^[^=]*=/, "", value)
      gsub(/^[[:space:]"\047]+|[[:space:]"\047]+$/, "", value)
      found=1
    }
    END { if (found) print value }
  ' "$file" 2>/dev/null || true
}

birdnet_user=''
if [ -r /etc/birdnet/birdnet.conf ]; then
  birdnet_user=$(conf_value /etc/birdnet/birdnet.conf BIRDNET_USER)
fi
if [ -z "$birdnet_user" ]; then
  while IFS=: read -r candidate _ uid _ _ candidate_home shell; do
    if [ "$uid" -ge 1000 ] && [ "$uid" -lt 65534 ] \
      && [[ "$shell" != *nologin ]] && [[ "$shell" != *false ]] \
      && [ -d "$candidate_home/BirdNET-Pi" ]; then
      birdnet_user=$candidate
      break
    fi
  done < <(getent passwd)
fi
[[ "$birdnet_user" =~ ^[A-Za-z_][A-Za-z0-9_-]*$ ]] \
  || fail "could not resolve the BirdNET-Pi user"

passwd_row=$(getent passwd "$birdnet_user")
[ -n "$passwd_row" ] || fail "BirdNET-Pi user does not exist"
birdnet_home=$(printf '%s\n' "$passwd_row" | cut -d: -f6)
birdnet_group=$(id -gn "$birdnet_user")
if ! [[ "$birdnet_home" =~ ^/[A-Za-z0-9._/-]+$ \
  && "$birdnet_home" != *'..'* ]]; then
  fail "BirdNET-Pi home path is not safe"
fi
birdnet_home=$(readlink -f -- "$birdnet_home") \
  || fail "BirdNET-Pi home path was not found"

repo_dir=$birdnet_home/BirdNET-Pi
if [ -L "$repo_dir" ] || [ ! -d "$repo_dir" ]; then
  fail "BirdNET-Pi checkout path is not safe"
fi
conf_link=/etc/birdnet/birdnet.conf
if [ -e "$conf_link" ] || [ -L "$conf_link" ]; then
  conf_path=$(readlink -f "$conf_link")
else
  conf_path=$repo_dir/birdnet.conf
fi
case "$conf_path" in
  "$repo_dir/birdnet.conf"|/etc/birdnet/birdnet.conf) ;;
  *) fail "BirdNET-Pi config path is not safe" ;;
esac

allowed_unit() {
  case "${1-}" in
    birdnet_recording|birdnet_analysis|birdnet_log|birdnet_stats|spectrogram_viewer|livestream|chart_viewer|icecast2|caddy|php8.2-fpm|php8.3-fpm|php8.4-fpm) return 0 ;;
    *) return 1 ;;
  esac
}

valid_number() {
  local value=$1 minimum=$2 maximum=$3
  [ "${#value}" -le 32 ] || return 1
  [[ "$value" =~ ^-?[0-9]+([.][0-9]+)?$ ]] || return 1
  awk -v n="$value" -v lo="$minimum" -v hi="$maximum" \
    'BEGIN { exit !(n >= lo && n <= hi) }'
}

valid_config_value() {
  local key=$1 value=$2
  case "$key" in
    CONFIDENCE) valid_number "$value" 0.05 0.99 ;;
    SENSITIVITY) valid_number "$value" 0.5 1.5 ;;
    SF_THRESH) valid_number "$value" 0.0005 0.99 ;;
    OVERLAP) valid_number "$value" 0 2.5 ;;
    LATITUDE) valid_number "$value" -90 90 ;;
    LONGITUDE) valid_number "$value" -180 180 ;;
    MAX_FILES_SPECIES)
      [[ "$value" =~ ^[0-9]{1,6}$ ]] && [ "$value" -le 100000 ]
      ;;
    PURGE_THRESHOLD)
      [[ "$value" =~ ^[0-9]{1,2}$ ]] && [ "$value" -ge 50 ] && [ "$value" -le 99 ]
      ;;
    FULL_DISK) [ "$value" = purge ] || [ "$value" = keep ] ;;
    COLLAGE_LABELS) [ "$value" = on ] || [ "$value" = off ] ;;
    SITE_NAME)
      [ "${#value}" -le 60 ] && [[ "$value" =~ ^[A-Za-z0-9\ _.,\047-]*$ ]]
      ;;
    GEMINI_API_KEY)
      [ "${#value}" -le 200 ] && [[ "$value" =~ ^[A-Za-z0-9_.\/+\=:-]*$ ]]
      ;;
    EBIRD_API_KEY)
      [ "${#value}" -le 120 ] && [[ "$value" =~ ^[A-Za-z0-9_.\/+\=:-]*$ ]]
      ;;
    *) return 1 ;;
  esac
}

quote_config_value() {
  local value=$1
  if [ -z "$value" ] || [[ "$value" =~ [^A-Za-z0-9._/+:-] ]]; then
    value=${value//\\/\\\\}
    value=${value//\"/\\\"}
    printf '"%s"' "$value"
  else
    printf '%s' "$value"
  fi
}

set_config_values() {
  if [ "$#" -lt 2 ] || [ $(( $# % 2 )) -ne 0 ]; then
    fail "config update requires key and value pairs"
  fi
  [ "$#" -le 24 ] || fail "too many config values"

  local key value quoted updates_temp config_temp
  declare -A seen=()
  [ -f "$conf_path" ] || fail "BirdNET-Pi config was not found"
  updates_temp=$(mktemp) || fail "could not create config update"
  config_temp=$(mktemp "$(dirname "$conf_path")/.birdnet.conf.XXXXXX") \
    || fail "could not create config update"
  trap 'rm -f "${updates_temp-}" "${config_temp-}"' EXIT

  while [ "$#" -gt 0 ]; do
    key=$1
    value=$2
    shift 2
    valid_config_value "$key" "$value" || fail "invalid config value for $key"
    [ -z "${seen[$key]+set}" ] || fail "duplicate config key: $key"
    seen[$key]=1
    quoted=$(quote_config_value "$value")
    printf '%s\t%s\n' "$key" "$quoted" >>"$updates_temp"
  done

  if ! awk -F '\t' '
    NR == FNR {
      replacement[$1]=$2
      order[++count]=$1
      next
    }
    /^[[:space:]]*[A-Z_][A-Z0-9_]*[[:space:]]*=/ {
      key=$0
      sub(/^[[:space:]]*/, "", key)
      sub(/[[:space:]]*=.*$/, "", key)
      if (key in replacement) {
        print key "=" replacement[key]
        written[key]=1
        next
      }
    }
    { print }
    END {
      for (position=1; position<=count; position++) {
        key=order[position]
        if (!(key in written)) print key "=" replacement[key]
      }
    }
  ' "$updates_temp" "$conf_path" >"$config_temp"; then
    fail "could not update config"
  fi
  chown "$birdnet_user:$birdnet_group" "$config_temp"
  chmod 0640 "$config_temp"
  mv -fT -- "$config_temp" "$conf_path"
  rm -f "$updates_temp" "$config_temp"
  trap - EXIT
}

read_config_values() {
  local count=$1 index key value trailing
  local -a values=()
  if ! [[ "$count" =~ ^[1-9][0-9]?$ ]] \
    || [ "$count" -lt 1 ] || [ "$count" -gt 12 ]; then
    fail "config input count is not allowed"
  fi

  for ((index=0; index<count; index++)); do
    IFS= read -r -d '' key || fail "incomplete config input"
    IFS= read -r -d '' value || fail "incomplete config input"
    values+=("$key" "$value")
  done
  trailing=$(od -An -N1 -tx1) || fail "could not read config input"
  if [ -n "${trailing//[[:space:]]/}" ]; then
    fail "unexpected config input"
  fi
  set_config_values "${values[@]}"
}

action=${1:-version}
case "$action" in
  version)
    [ "$#" -eq 1 ] || fail "unexpected arguments"
    printf '{"ok":true,"version":%s}\n' "$CONTROL_VERSION"
    ;;
  restart)
    [ "$#" -eq 2 ] || fail "restart requires one unit"
    allowed_unit "$2" || fail "unit is not allowed"
    if /bin/systemctl restart "$2"; then
      printf '{"ok":true,"unit":"%s"}\n' "$(json_escape "$2")"
    else
      fail "service restart failed"
    fi
    ;;
  journal)
    [ "$#" -eq 3 ] || fail "journal requires a unit and line count"
    allowed_unit "$2" || fail "unit is not allowed"
    if ! [[ "$3" =~ ^[0-9]{1,3}$ ]] || [ "$3" -lt 10 ] || [ "$3" -gt 500 ]; then
      fail "journal line count is not allowed"
    fi
    exec /bin/journalctl -u "$2" --no-pager -n "$3" -o short-iso
    ;;
  config-set)
    [ "$#" -eq 3 ] || fail "config-set requires a key and value"
    set_config_values "$2" "$3"
    printf '{"ok":true,"key":"%s"}\n' "$(json_escape "$2")"
    ;;
  config-set-many)
    if [ "$#" -lt 3 ] || [ $(( ($# - 1) % 2 )) -ne 0 ]; then
      fail "config-set-many requires key and value pairs"
    fi
    shift
    set_config_values "$@"
    printf '{"ok":true,"updated":%s}\n' "$(( $# / 2 ))"
    ;;
  config-set-stdin)
    [ "$#" -eq 2 ] || fail "config-set-stdin requires a pair count"
    read_config_values "$2"
    printf '{"ok":true,"updated":%s}\n' "$2"
    ;;
  *) fail "unknown action" ;;
esac
