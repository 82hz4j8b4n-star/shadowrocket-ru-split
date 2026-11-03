#!/usr/bin/env bash
# Builds the Shadowrocket config and the matching server-side lists from the upstream sources:
#   v2fly category-ru                      Russian sites                       -> DIRECT
#   runetfreedom ru-available-only-inside  only work from inside Russia        -> DIRECT (always)
#   runetfreedom ru-blocked                blocked by Russia                   -> PROXY
#   never-direct.txt / extra-ru-domains.txt  local corrections
#   HaGeZi Pro + TIF medium                ads, trackers, malware (DIRECT part only) -> REJECT
# Then checks the result; a failed check stops here, so nothing broken gets published.
#
# usage: ./build.sh [out-dir]     (default: ./out)
# Writes out-dir/shadowrocket.conf, client-direct.dat and client-proxy.dat.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
out=$(mkdir -p "${1:-$here/out}" && cd "${1:-$here/out}" && pwd)
tools=$here/tools
cache=$here/.cache
export UPDATE_URL=${UPDATE_URL:-https://raw.githubusercontent.com/82hz4j8b4n-star/shadowrocket-ru-split/dist/shadowrocket.conf}

rm -rf "$cache"
mkdir -p "$cache"/{dlc,runet,hagezi,tranco}

echo "==> Russian sites (v2fly category-ru)"
python3 -I "$tools/flatten_dlc.py" "$cache/dlc" category-ru >"$cache/ru-rules.txt"

echo "==> Blocked and inside-only lists (runetfreedom)"
curl -fsSL --retry 3 -o "$cache/runet/geosite-ru-only.dat" \
  https://github.com/runetfreedom/russia-blocked-geosite/releases/latest/download/geosite-ru-only.dat
for c in ru-blocked ru-available-only-inside; do
  python3 -I "$tools/geosite_dump.py" "$cache/runet/geosite-ru-only.dat" "$c" >"$cache/runet/$c.txt"
done

echo "==> Ad, tracker and malware lists (HaGeZi)"
for n in pro tif.medium; do
  curl -fsSL --retry 3 -o "$cache/hagezi/$n.txt" \
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/$n-onlydomains.txt"
done

echo "==> Building"
python3 -I "$tools/build_conf.py" "$cache/ru-rules.txt" "$here/extra-ru-domains.txt" "$here/never-direct.txt" \
  "$cache/runet/ru-available-only-inside.txt" "$cache/runet/ru-blocked.txt" \
  "$out/shadowrocket.conf" "$out" "$cache/hagezi/pro.txt" "$cache/hagezi/tif.medium.txt"

echo "==> Checking (named test sites, list sizes, the world's top 20,000 sites)"
curl -fsSL --retry 3 -o "$cache/tranco/top.zip" https://tranco-list.eu/top-1m.csv.zip
python3 -I -c 'import sys, zipfile; zipfile.ZipFile(sys.argv[1]).extractall(sys.argv[2])' \
  "$cache/tranco/top.zip" "$cache/tranco"
python3 -I "$tools/check_rules.py" "$out/shadowrocket.conf" \
  "$cache/runet/ru-available-only-inside.txt" "$cache/tranco/top-1m.csv"
