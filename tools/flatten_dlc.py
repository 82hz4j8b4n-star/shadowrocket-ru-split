"""Flatten a v2fly domain-list-community category (following include:) into Shadowrocket rules.

usage: python3 -I flatten_dlc.py <cache-dir> <category> > rules.txt
Downloads each list file into <cache-dir> once. Skips regexp: entries and entries tagged @ads.
"""
import os
import sys
import urllib.request

BASE = "https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/"
COVERED_TLDS = ("ru", "su", "xn--p1ai")  # get their own DOMAIN-SUFFIX rules


def fetch(cache, name):
    path = os.path.join(cache, name)
    if not os.path.exists(path):
        with urllib.request.urlopen(BASE + name, timeout=30) as r:
            data = r.read()
        with open(path, "wb") as f:
            f.write(data)
    with open(path, encoding="utf-8") as f:
        return f.read().splitlines()


def walk(cache, name, seen, out):
    if name in seen:
        return
    seen.add(name)
    for line in fetch(cache, name):
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        entry, attrs = parts[0], parts[1:]
        if any(a == "@ads" for a in attrs):
            continue
        kind, _, value = entry.partition(":")
        if not value:
            kind, value = "domain", entry
        if kind == "include":
            walk(cache, value, seen, out)
        elif kind in ("domain", "full", "keyword"):
            out.add((kind, value.lower()))


def main():
    cache, category = sys.argv[1], sys.argv[2]
    os.makedirs(cache, exist_ok=True)
    found = set()
    walk(cache, category, set(), found)

    suffixes = sorted(v for k, v in found if k == "domain")
    suffix_set = set(suffixes)

    def covered(d):
        labels = d.split(".")
        if labels[-1] in COVERED_TLDS:
            return True
        # drop subdomains of another listed suffix
        return any(".".join(labels[i:]) in suffix_set for i in range(1, len(labels)))

    rules = []
    for d in suffixes:
        if d in COVERED_TLDS or covered(d):
            continue
        rules.append(f"DOMAIN-SUFFIX,{d},DIRECT")
    for k, v in sorted(found):
        if k == "full" and not covered(v) and v not in suffix_set:
            rules.append(f"DOMAIN,{v},DIRECT")
        elif k == "keyword":
            rules.append(f"DOMAIN-KEYWORD,{v},DIRECT")
    print("\n".join(rules))
    print(f"{len(rules)} rules from {len(found)} entries", file=sys.stderr)


main()
