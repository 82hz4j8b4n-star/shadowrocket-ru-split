#!/usr/bin/env bash
# Publishes a build to the `dist` branch, but only when the rules changed (a new build date alone
# doesn't count). The previous client-proxy.dat is kept as client-proxy-prev.dat, so a server that
# already has the new lists still accepts what a client on yesterday's config sends.
#
# usage: ./publish.sh <out-dir>     (run from a clone with push access; CI does this daily)
set -euo pipefail

out=$(cd "$1" && pwd)
repo=$(cd "$(dirname "$0")" && pwd)
wt=$(mktemp -d)
trap 'git -C "$repo" worktree remove --force "$wt" 2>/dev/null || rm -rf "$wt"' EXIT

cd "$repo"
if git ls-remote --exit-code --heads origin dist >/dev/null 2>&1; then
  git fetch -q origin dist
  git worktree add -q --detach "$wt" FETCH_HEAD
else
  git worktree add -q --orphan -b dist "$wt"
fi

strip() { grep -v '^# Built ' "$1"; }
if [[ -f $wt/shadowrocket.conf ]] &&
   cmp -s <(strip "$out/shadowrocket.conf") <(strip "$wt/shadowrocket.conf") &&
   cmp -s "$out/client-direct.dat" "$wt/client-direct.dat" &&
   cmp -s "$out/client-proxy.dat" "$wt/client-proxy.dat"; then
  echo "Rules unchanged; nothing to publish"
  exit 0
fi

if [[ -f $wt/client-proxy.dat ]]; then
  cp "$wt/client-proxy.dat" "$wt/client-proxy-prev.dat"
else
  cp "$out/client-proxy.dat" "$wt/client-proxy-prev.dat"
fi
# dist holds exactly this build: anything else there (lists of an earlier design) is removed
find "$wt" -mindepth 1 -maxdepth 1 ! -name .git ! -name client-proxy-prev.dat -exec rm -rf {} +
cp "$out/shadowrocket.conf" "$out/client-direct.dat" "$out/client-proxy.dat" "$wt/"
cat >"$wt/README.md" <<'EOF'
Published rules (built daily by the `build` workflow on `main`; don't edit here).

- `shadowrocket.conf`: the Shadowrocket config (add it in Shadowrocket from its raw URL)
- `client-direct.dat`, `client-proxy.dat`, `client-proxy-prev.dat`: the matching lists for the Xray server
EOF
cd "$wt"
git add -A
git -c user.name="github-actions[bot]" -c user.email="41898282+github-actions[bot]@users.noreply.github.com" \
  commit -q -m "Rules $(date -u +%F)"
git push -q origin HEAD:dist
echo "Published"
