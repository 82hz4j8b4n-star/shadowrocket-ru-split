"""Build the Shadowrocket config and the matching server-side lists from one set of inputs.

usage: python3 -I build_conf.py <ru-rules.txt> <extra-ru.txt> <never-direct.txt> <inside-only.txt>
                                <ru-blocked.txt> <out.conf> <server-dir> <blocklist> [<blocklist> ...]
  ru-rules.txt     DOMAIN-SUFFIX/DOMAIN lines from flatten_dlc.py (v2fly category-ru)
  extra-ru.txt     extra Russian domains, one per line (# comments allowed)
  never-direct.txt non-Russian domains the Russian lists include anyway: always PROXY
  inside-only.txt  runetfreedom ru-available-only-inside ("domain:x" lines): always DIRECT
  ru-blocked.txt   runetfreedom ru-blocked ("domain:x" lines): blocked in Russia, so PROXY
  server-dir       gets client-direct.dat and client-proxy.dat (geosite format) for Xray, so the
                   server refuses exactly what the client sends direct and accepts what it sends here
  blocklist        HaGeZi wildcard "onlydomains" lists; only entries that would go DIRECT are kept,
                   because everything going through the proxy is already filtered on the server
Set UPDATE_URL to the address the config is published at; it is written into [General] so
Shadowrocket keeps updating it from there.
"""
import datetime
import os
import sys

RU_TLDS = ("ru", "su", "xn--p1ai")

GENERAL = """\
# Shadowrocket split-tunnel config for Russia (updates itself daily)
# Built {date}. Source: https://github.com/82hz4j8b4n-star/shadowrocket-ru-split
#
# Russian sites                 -> DIRECT, resolved by Yandex's encrypted DNS (a Russian service)
# Russian sites Russia blocks   -> PROXY
# Everything else               -> PROXY, resolved on the server; nothing about it is looked up locally
# Server down                   -> proxied sites fail; they never fall back to the real connection
# Russian ad/tracker/malware domains are refused here; everything else is filtered on the server.

[General]
update-url = {update_url}
bypass-system = true
skip-proxy = 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, localhost, *.local, captive.apple.com
tun-excluded-routes = 10.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.0.2.0/24, 192.88.99.0/24, 192.168.0.0/16, 198.51.100.0/24, 203.0.113.0/24, 224.0.0.0/4, 255.255.255.255/32, 239.255.255.250/32
# DNS only for DIRECT (Russian) names; PROXY names are resolved remotely
dns-server = https://safe.dot.dns.yandex.net/dns-query
direct-dns-server = https://safe.dot.dns.yandex.net/dns-query
# The server's own name: uncensored resolvers, asked in parallel (the first answer wins), so a
# Russian resolver can never hand out a blocked answer for it
proxy-dns-server = https://1.1.1.1/dns-query, https://8.8.8.8/dns-query, https://9.9.9.9/dns-query
fallback-dns-server = system
dns-direct-system = false
# A Russian name that can't be resolved fails instead of being sent through the proxy
dns-direct-fallback-proxy = false
private-ip-answer = true
use-local-host-item-for-proxy = false
allow-dns-svcb = false
# Catch apps that use their own DNS server (8.8.8.8 etc.)
hijack-dns = *:53
ipv6 = false
prefer-ipv6 = false
icmp-auto-reply = true
always-reject-url-rewrite = false
# UDP the server can't carry is dropped, never sent directly
udp-policy-not-supported-behaviour = REJECT
# QUIC through the proxy is blocked so apps use TCP, which is faster and more reliable here
block-quic = all-proxy

[Host]
safe.dot.dns.yandex.net = 77.88.8.88
*.local = server:system
localhost = 127.0.0.1

[Rule]
"""


def read_list(path):
    out = set()
    for line in open(path, encoding="utf-8", errors="ignore"):
        line = line.split("#", 1)[0].strip().lower()
        if line.startswith("domain:"):
            line = line[len("domain:"):]
        if line and ":" not in line:
            out.add(line)
    return out


def under(d, suffixes):
    labels = d.split(".")
    return any(".".join(labels[i:]) in suffixes for i in range(len(labels)))


def minimal(domains):
    """Drop domains already covered by another (shorter) one in the set."""
    s = set(domains)
    return sorted(d for d in s if not under(d, s - {d}) or d in RU_TLDS)


# --- geosite.dat writer (protobuf: GeoSiteList{entry=1: GeoSite{country_code=1, domain=2: Domain{type=1, value=2}}})
def _varint(n):
    out = bytearray()
    while True:
        b = n & 0x7F; n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def _field(num, payload):
    return _varint(num << 3 | 2) + _varint(len(payload)) + payload


def write_geosite(path, code, suffixes, exact=()):
    site = _field(1, code.upper().encode())
    for d in sorted(suffixes):
        site += _field(2, _varint(1 << 3) + _varint(2) + _field(2, d.encode()))  # type 2 = domain
    for d in sorted(exact):
        site += _field(2, _varint(1 << 3) + _varint(3) + _field(2, d.encode()))  # type 3 = full
    open(path, "wb").write(_field(1, site))


def main():
    ru_rules_path, extra_path, never_path, inside_path, blocked_path, out_path, server_dir, *blocklists = sys.argv[1:]

    cat_suffix, cat_exact = set(), set()
    for r in open(ru_rules_path):
        r = r.strip()
        if r:
            kind, value, _ = r.split(",")
            (cat_suffix if kind == "DOMAIN-SUFFIX" else cat_exact).add(value)
    extra = read_list(extra_path)
    inside = read_list(inside_path)
    never = read_list(never_path)
    cat_suffix = {d for d in cat_suffix if not under(d, never)}
    cat_exact = {d for d in cat_exact if not under(d, never)}

    direct_suffix = set(RU_TLDS) | cat_suffix | extra | inside

    def goes_direct(d):
        return d in cat_exact or under(d, direct_suffix)

    # Blocked in Russia but would otherwise go direct -> PROXY (inside-only always wins)
    proxy_exc = minimal([d for d in read_list(blocked_path) if goes_direct(d) and not under(d, inside)]
                        + sorted(never))
    proxy_set = set(proxy_exc)

    reject = set()
    for path in blocklists:
        reject |= {d for d in read_list(path) if goes_direct(d)}
    reject = [d for d in minimal(reject) if d not in direct_suffix and d not in inside]

    lines = [GENERAL.format(date=datetime.date.today().isoformat(), update_url=os.environ["UPDATE_URL"])]
    lines.append(f"# 1. Russian ad, tracker and malware domains (HaGeZi Pro + Threat Intel): {len(reject)}")
    lines += [f"DOMAIN-SUFFIX,{d},REJECT" for d in reject]
    lines += ["", "# 2. Local network"]
    lines += [f"IP-CIDR,{n},DIRECT,no-resolve" for n in
              ("192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12", "127.0.0.0/8", "169.254.0.0/16")]
    lines += ["", f"# 3. Russian services that only work from inside Russia (runetfreedom): {len(inside)}"]
    lines += [f"DOMAIN-SUFFIX,{d},DIRECT" for d in sorted(inside)]
    lines += ["", f"# 4. Russian sites that Russia blocks (runetfreedom ru-blocked), and non-Russian sites the\n#    Russian lists include by mistake: {len(proxy_exc)}"]
    lines += [f"DOMAIN-SUFFIX,{d},PROXY" for d in proxy_exc]
    lines += ["", "# 5. Russian top-level domains"]
    lines += [f"DOMAIN-SUFFIX,{t},DIRECT" for t in RU_TLDS]
    lines += ["", "# 6. Russian services on other domains (v2fly category-ru, plus extras)"]
    lines += [f"DOMAIN-SUFFIX,{d},DIRECT" for d in sorted(extra)]
    lines += [f"DOMAIN-SUFFIX,{d},DIRECT" for d in sorted(cat_suffix - extra)]
    lines += [f"DOMAIN,{d},DIRECT" for d in sorted(cat_exact)]
    lines += ["", "# 7. Connections an app makes straight to a Russian IP (no DNS lookup is triggered)",
              "GEOIP,RU,DIRECT,no-resolve", "", "# 8. Everything else: through the proxy", "FINAL,PROXY"]
    open(out_path, "w").write("\n".join(lines) + "\n")

    os.makedirs(server_dir, exist_ok=True)
    write_geosite(os.path.join(server_dir, "client-direct.dat"), "client-direct",
                  direct_suffix - proxy_set, cat_exact)
    write_geosite(os.path.join(server_dir, "client-proxy.dat"), "client-proxy", proxy_set)
    print(f"reject {len(reject)}, inside-only {len(inside)}, blocked->proxy {len(proxy_exc)}, "
          f"direct suffixes {len(direct_suffix)}, exact {len(cat_exact)}", file=sys.stderr)


main()
