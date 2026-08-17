#!/usr/bin/env bash
# Render BirdNET-Pi's Caddyfile without evaluating birdnet.conf as shell code.

set -euo pipefail
IFS=$'\n\t'
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

conf=/etc/birdnet/birdnet.conf
site_overlay=/etc/caddy/avian-site-overlay.caddy
[ -r "$conf" ] || { echo "BirdNET-Pi config was not found" >&2; exit 1; }

conf_value() {
  local key=$1
  awk -v wanted="$key" '
    $0 ~ "^[[:space:]]*" wanted "[[:space:]]*=" {
      value=$0
      sub(/^[^=]*=/, "", value)
      gsub(/^[[:space:]"\047]+|[[:space:]"\047]+$/, "", value)
      found=1
    }
    END { if (found) print value }
  ' "$conf"
}

BIRDNET_USER=$(conf_value BIRDNET_USER)
EXTRACTED=$(conf_value EXTRACTED)
CADDY_PWD=$(conf_value CADDY_PWD)
[[ "$BIRDNET_USER" =~ ^[A-Za-z_][A-Za-z0-9_-]*$ ]] \
  || { echo "Invalid BirdNET-Pi user" >&2; exit 1; }
[[ "$EXTRACTED" =~ ^/[A-Za-z0-9._/-]+$ ]] && [[ "$EXTRACTED" != *'..'* ]] \
  || { echo "Invalid BirdNET-Pi webroot" >&2; exit 1; }

fpm_sock=$(find /run/php -maxdepth 1 -type s -name 'php*-fpm.sock' -print 2>/dev/null | sort | head -n 1 || true)
fpm_sock=${fpm_sock:-/run/php/php-fpm.sock}

legacy_gate=''
legacy_handles=''
if [ -n "$CADDY_PWD" ]; then
  hashword=$(printf '%s\n' "$CADDY_PWD" | caddy hash-password)
  legacy_gate="  basicauth @legacyAdmin {
    birdnet $hashword
  }"
else
  legacy_handles="  # Keep the stock BirdNET-Pi pages usable on the station's
  # private address when no password is configured. A public hostname or any
  # inbound proxy marker falls through to the terminal legacy 404.
  @directLegacyAdmin {
    path /index.php* /views.php* /play.php* /spectrogram.php* /overview.php* /stats.php* /todays_detections.php* /history.php* /weekly_report.php* /Processed* /log /log/* /stats /stats/*
    remote_ip private_ranges
    header_regexp localLegacyHost Host (?i)^(localhost|[a-z0-9][a-z0-9.-]*[.]local|10[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}|127[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}|192[.]168[.][0-9]{1,3}[.][0-9]{1,3}|172[.](1[6-9]|2[0-9]|3[01])[.][0-9]{1,3}[.][0-9]{1,3}|169[.]254[.][0-9]{1,3}[.][0-9]{1,3}|[[]::1[]]|[[]f[cd][0-9a-f:]*[]]|[[]fe[89ab][0-9a-f:]*[]])(:[0-9]{1,5})?$
    not header Forwarded *
    not header X-Forwarded-For *
    not header X-Forwarded-Host *
    not header X-Forwarded-Proto *
    not header X-Forwarded-Port *
    not header X-Forwarded-Server *
    not header X-Forwarded-Scheme *
    not header X-Real-Ip *
    not header Cf-Connecting-Ip *
    not header Cf-Connecting-IPv6 *
    not header Cf-Pseudo-IPv4 *
    not header Cf-Ray *
    not header Cf-Visitor *
  }
  handle @directLegacyAdmin {
    php_fastcgi unix/$fpm_sock {
      try_files {path} {path}/index.html {path}/index.php =404
    }
    reverse_proxy @legacyLogProxy localhost:8080
    reverse_proxy @legacyStatsProxy localhost:8501
    reverse_proxy @legacyTerminalProxy localhost:8888
    file_server
  }
  handle @legacyAdmin {
    respond 404
  }"
fi

site_overlay_import=''
if [ -e "$site_overlay" ] || [ -L "$site_overlay" ]; then
  if [ -L "$site_overlay" ] || [ ! -f "$site_overlay" ]; then
    echo "Refusing unsafe Caddy site overlay: expected a regular file" >&2
    exit 1
  fi

  caddy_group=$(getent group caddy) \
    || { echo "Refusing Caddy site overlay: caddy group was not found" >&2; exit 1; }
  caddy_gid=$(printf '%s\n' "$caddy_group" | awk -F: 'NR == 1 { print $3 }')
  [ -n "$caddy_gid" ] \
    || { echo "Refusing Caddy site overlay: caddy group was not found" >&2; exit 1; }
  site_overlay_stat=$(stat -c '%u:%g:%a:%h' -- "$site_overlay")
  [ "$site_overlay_stat" = "0:$caddy_gid:640:1" ] \
    || { echo "Refusing unsafe Caddy site overlay: expected root:caddy 0640 with one link" >&2; exit 1; }

  site_overlay_import="  import $site_overlay"$'\n'
fi

mkdir -p /etc/caddy
if [ -f /etc/caddy/Caddyfile ]; then
  if [ ! -f /etc/caddy/Caddyfile.original ]; then
    cp -p /etc/caddy/Caddyfile /etc/caddy/Caddyfile.original
  fi
  cp -p /etc/caddy/Caddyfile /etc/caddy/Caddyfile.previous
fi

temp=$(mktemp /etc/caddy/.Caddyfile.XXXXXX)
trap 'rm -f "$temp"' EXIT
cat >"$temp" <<EOF
# Managed by AvianVisitors. The prior file is Caddyfile.previous.
http:// {
${site_overlay_import}  root * $EXTRACTED

  @shell path / /index.html
  header @shell Cache-Control "no-cache"

  # The published frame (frame/install-publish.sh) is re-rendered on a timer, so
  # a heuristically-cached copy shows yesterday's birds. no-cache forces
  # revalidation while still allowing the 304 the frame Pi's conditional GET
  # relies on. A no-op where the publisher was never installed and the path does
  # not exist.
  @frame path /frame.png
  header @frame Cache-Control "no-cache"

  # BirdNET-Pi's older PHP tools and reverse-proxied consoles do not share
  # AvianVisitors' session gate. Protect the whole legacy surface with the
  # configured password, or limit it to direct read pages when none exists.
  @legacyAdmin {
    path /index.php* /views.php* /play.php* /spectrogram.php* /overview.php* /stats.php* /todays_detections.php* /history.php* /weekly_report.php* /scripts* /Processed* /terminal /terminal/* /log /log/* /stats /stats/* /phpsysinfo*
  }
  @legacyLogProxy path /log /log/*
  @legacyStatsProxy path /stats /stats/*
  @legacyTerminalProxy path /terminal /terminal/*
$legacy_gate
$legacy_handles

  # Only finished bird PNGs and the two stamp assets are public beneath the
  # writable artwork tree. Generator state, logs, references, staging files,
  # and anything executable remain private even when they exist on disk.
  @publicIllustration path_regexp publicIllustration ^/avian/assets/illustrations/[A-Za-z0-9][A-Za-z0-9_-]*[.]png$
  handle @publicIllustration {
    file_server
  }
  @publicStampReference path /avian/assets/references/sparrow-blossom-single-v2.png /avian/assets/references/sparrow-blossom-pair-v2.png
  handle @publicStampReference {
    file_server
  }
  handle /avian/assets/* {
    respond 404
  }

  # The webroot also links the frontend asset directory. Publish only the
  # checked-in stamp artwork; local recording previews and future working
  # files beneath /assets remain private.
  @publicFrontendStamp path /assets/stamp/owl-pale-treeline.jpg /assets/stamp/paper-texture-grey.png /assets/stamp/rough-concrete-cc0.png
  handle @publicFrontendStamp {
    file_server
  }
  handle /assets/* {
    respond 404
  }

  # Only the reviewed production API entry points are published. This keeps
  # deferred or locally generated handlers private if they remain in an
  # existing checkout during an update, including their source text.
  @unknownAvianApi {
    path /avian/api/*
    not path /avian/api/archive.php /avian/api/birdnet-api.php /avian/api/birdnet-status.php /avian/api/config.php /avian/api/cutout.php /avian/api/export.php /avian/api/generate.php /avian/api/maintenance.php /avian/api/menu.php /avian/api/recording.php /avian/api/spectrogram.php /avian/api/wiki.php
  }
  handle @unknownAvianApi {
    respond 404
  }

  # The top-level webroot links the repository's avian directory so the API
  # and artwork share stable paths. Everything else beneath it stays private;
  # production frontend files are linked at the site root instead.
  @privateAvian {
    path /avian/*
    not path /avian/api/* /avian/assets/*
  }
  handle @privateAvian {
    respond 404
  }

  # A microphone stream can contain nearby conversation. Reject proxy
  # markers first, then allow only a direct private-network peer.
  handle /stream* {
    route {
      @forwarded header Forwarded *
      respond @forwarded 404
      @xForwardedFor header X-Forwarded-For *
      respond @xForwardedFor 404
      @xForwardedHost header X-Forwarded-Host *
      respond @xForwardedHost 404
      @xForwardedProto header X-Forwarded-Proto *
      respond @xForwardedProto 404
      @xForwardedPort header X-Forwarded-Port *
      respond @xForwardedPort 404
      @xForwardedServer header X-Forwarded-Server *
      respond @xForwardedServer 404
      @xForwardedScheme header X-Forwarded-Scheme *
      respond @xForwardedScheme 404
      @xRealIp header X-Real-Ip *
      respond @xRealIp 404
      @cloudflare header Cf-Connecting-Ip *
      respond @cloudflare 404
      @cloudflareIPv6 header Cf-Connecting-IPv6 *
      respond @cloudflareIPv6 404
      @cloudflarePseudoIPv4 header Cf-Pseudo-IPv4 *
      respond @cloudflarePseudoIPv4 404
      @cloudflareRay header Cf-Ray *
      respond @cloudflareRay 404
      @cloudflareVisitor header Cf-Visitor *
      respond @cloudflareVisitor 404
      @directLocal remote_ip private_ranges
      reverse_proxy @directLocal localhost:8000
      respond 404
    }
  }

  handle /By_Date/* {
    file_server
  }
  handle /Charts/* {
    file_server
  }

  # Caddy adds X-Forwarded-* fields when it talks to PHP-FPM, even for a
  # direct browser on the LAN. Preserve a decision made from the raw request
  # in a FastCGI variable that the browser cannot forge.
  @directAdminApi {
    path /avian/api/*
    remote_ip private_ranges
    not header Forwarded *
    not header X-Forwarded-For *
    not header X-Forwarded-Host *
    not header X-Forwarded-Proto *
    not header X-Forwarded-Port *
    not header X-Forwarded-Server *
    not header X-Forwarded-Scheme *
    not header X-Real-Ip *
    not header Cf-Connecting-Ip *
    not header Cf-Connecting-IPv6 *
    not header Cf-Pseudo-IPv4 *
    not header Cf-Ray *
    not header Cf-Visitor *
  }
  handle @directAdminApi {
    php_fastcgi unix/$fpm_sock {
      try_files {path} {path}/index.html {path}/index.php =404
      env AVIAN_DIRECT_LOCAL 1
    }
  }
  handle /avian/api/* {
    php_fastcgi unix/$fpm_sock {
      try_files {path} {path}/index.html {path}/index.php =404
      env AVIAN_DIRECT_LOCAL 0
    }
  }
  handle {
    php_fastcgi unix/$fpm_sock {
      try_files {path} {path}/index.html {path}/index.php =404
    }
    reverse_proxy @legacyLogProxy localhost:8080
    reverse_proxy @legacyStatsProxy localhost:8501
    reverse_proxy @legacyTerminalProxy localhost:8888
    file_server
  }
}
EOF

caddy fmt --overwrite "$temp"
caddy validate --config "$temp" --adapter caddyfile
install -o root -g root -m 0644 "$temp" /etc/caddy/Caddyfile
rm -f "$temp"
trap - EXIT
systemctl reload-or-restart caddy
