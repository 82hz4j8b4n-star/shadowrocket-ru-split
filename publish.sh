#!/usr/bin/env bash
# Publishes a build to the `dist` branch, but only when the rules changed (a new build date alone
# doesn't count).
#
# usage: ./publish.sh <out-dir>     (run from a clone with push access; CI does this daily)
set -euo pipefail

out=$(cd "$1" && pwd)
repo=$(cd "$(dirname "$0")" && pwd)
files=(shadowrocket.conf client-claude.dat client-claude-ip.dat)
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
same=1
for f in "${files[@]}"; do
  if [[ ! -f $wt/$f ]]; then same=0
  elif [[ $f == *.conf ]]; then cmp -s <(strip "$out/$f") <(strip "$wt/$f") || same=0
  else cmp -s "$out/$f" "$wt/$f" || same=0
  fi
done
if [[ $same = 1 ]]; then
  echo "Rules unchanged; nothing to publish"
  exit 0
fi

git -C "$wt" rm -q --ignore-unmatch client-direct.dat client-proxy.dat client-proxy-prev.dat
for f in "${files[@]}"; do cp "$out/$f" "$wt/"; done
cat >"$wt/README.md" <<'EOF'
Published rules (built daily by the `build` workflow on `main`; don't edit here).

- `shadowrocket.conf`: the Shadowrocket config (add it in Shadowrocket from its raw URL)
- `client-claude.dat`, `client-claude-ip.dat`: the config's Claude rules for the Claude server's Xray
  (geosite and geoip format, list `claude`)
EOF
cd "$wt"
git add -A
git -c user.name="github-actions[bot]" -c user.email="41898282+github-actions[bot]@users.noreply.github.com" \
  commit -q -m "Rules $(date -u +%F)"
git push -q origin HEAD:dist
echo "Published"
