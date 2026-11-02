"""Build the Shadowrocket config and the matching lists for the Claude server from one set of inputs.

usage: python3 -I build_conf.py <ru-rules.txt> <extra-ru.txt> <never-direct.txt> <inside-only.txt>
                                <ru-blocked.txt> <claude-route.txt> <provider-direct.txt>
                                <out.conf> <server-dir> <blocklist> [<blocklist> ...]
  ru-rules.txt        DOMAIN-SUFFIX/DOMAIN lines from flatten_dlc.py (v2fly category-ru)
  extra-ru.txt        extra Russian domains, one per line (# comments allowed)
  never-direct.txt    non-Russian domains the Russian lists include anyway: never DIRECT
  inside-only.txt     runetfreedom ru-available-only-inside ("domain:x" lines): always DIRECT
  ru-blocked.txt      runetfreedom ru-blocked ("domain:x" lines): blocked in Russia, so the VPN
  claude-route.txt    Claude and Anthropic: domains, full:hosts and IP ranges for the Claude group
  provider-direct.txt the VPN provider's subscription server: always DIRECT
  server-dir          gets client-claude.dat (geosite) and client-claude-ip.dat (geoip) for Xray, so
                      the Claude server accepts exactly what the client sends it
  blocklist           HaGeZi wildcard "onlydomains" lists; only entries that would go DIRECT are kept
                      (the config stays small enough for the iPhone; the rest is left to the VPN)
Set UPDATE_URL to the address the config is published at; it is written into [General] so
Shadowrocket keeps updating it from there.
"""
import datetime
import ipaddress
import os
import re
import sys

RU_TLDS = ("ru", "su", "xn--p1ai")

# Proxy groups. The servers come from the Shadowrocket home screen: the Claude server is the one
# named CLAUDE_NODE (the #name in its link), every other server belongs to the VPN subscription.
CLAUDE = "Claude"
CLAUDE_NODE = "Claude-DE"
OLD_NODES = ("Germany",)  # the Claude server's name before 2026-11-02; never part of Auto
AUTO = "Auto"
# Auto tests its servers against a site Russia blocks, so a server that comes out inside Russia
# (or a placeholder entry such as "subscription expires on ...") never gets picked
AUTO_TEST_URL = "https://www.youtube.com/generate_204"

DOMAIN = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$")

GENERAL = """\
# Shadowrocket split-tunnel config for Russia (updates itself daily)
# Built {date}. Source: https://github.com/82hz4j8b4n-star/shadowrocket-ru-split
#
# Claude and Anthropic          -> group "Claude": only the Claude server, never the VPN or direct
# Russian sites                 -> DIRECT, resolved by Yandex's encrypted DNS (a Russian service)
# Russian sites Russia blocks   -> group "Auto"
# Everything else               -> group "Auto": the fastest server of the VPN subscription, resolved
#                                  there; nothing about it is looked up locally
# A route down                  -> its sites fail; they never fall back to another route
# Needs Global Routing "Config": the "Proxy" mode ignores groups and rules.
# Russian ad/tracker/malware domains are refused here.

[General]
update-url = {update_url}
bypass-system = true
skip-proxy = 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, localhost, *.local, captive.apple.com
tun-excluded-routes = 10.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.0.2.0/24, 192.88.99.0/24, 192.168.0.0/16, 198.51.100.0/24, 203.0.113.0/24, 224.0.0.0/4, 255.255.255.255/32, 239.255.255.250/32
# DNS only for DIRECT (Russian) names; names that go through a server are resolved remotely
dns-server = https://safe.dot.dns.yandex.net/dns-query
direct-dns-server = https://safe.dot.dns.yandex.net/dns-query
# The servers' own names: uncensored resolvers, asked in parallel (the first answer wins), so a
# Russian resolver can never hand out a blocked answer for a VPN server
proxy-dns-server = https://1.1.1.1/dns-query, https://8.8.8.8/dns-query, https://9.9.9.9/dns-query
fallback-dns-server = system
dns-direct-system = false
# A Russian name that can't be resolved fails instead of being sent through a server
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
# UDP a server can't carry is dropped, never sent directly
udp-policy-not-supported-behaviour = REJECT
# QUIC through a server is blocked so apps use TCP, which is faster and more reliable here
block-quic = all-proxy

[Host]
safe.dot.dns.yandex.net = 77.88.8.88
*.local = server:system
localhost = 127.0.0.1

[Proxy Group]
# Only the Claude server. If it is missing or down, Claude fails (REJECT); it never goes another way.
{claude} = select,{claude_node},REJECT,policy-select-name={claude_node}
# Every other server (the VPN subscription), the fastest that reaches a site Russia blocks; tested
# every 10 minutes, switching only for a 50 ms gain
{auto} = url-test,policy-regex-filter={auto_regex},url={auto_url},interval=600,timeout=5,tolerance=50

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


def read_route(path):
    """claude-route.txt -> (suffixes, exact hosts, IP networks); stops on anything malformed."""
    suffix, exact, nets = set(), set(), []
    for n, line in enumerate(open(path, encoding="utf-8"), 1):
        e = line.split("#", 1)[0].strip().lower()
        if not e:
            continue
        if "/" in e:
            nets.append(ipaddress.ip_network(e, strict=True))
            continue
        target = exact if e.startswith("full:") else suffix
        e = e.removeprefix("full:")
        if not DOMAIN.match(e):
            raise SystemExit(f"{path}:{n}: not a domain: {e}")
        target.add(e)
    return suffix, exact - {d for d in exact if under(d, suffix)}, nets


def under(d, suffixes):
    labels = d.split(".")
    return any(".".join(labels[i:]) in suffixes for i in range(len(labels)))


def minimal(domains):
    """Drop domains already covered by another (shorter) one in the set."""
    s = set(domains)
    return sorted(d for d in s if not under(d, s - {d}) or d in RU_TLDS)


# --- Xray .dat writers (protobuf)
#   geosite: GeoSiteList{entry=1: GeoSite{country_code=1, domain=2: Domain{type=1, value=2}}}
#   geoip:   GeoIPList{entry=1: GeoIP{country_code=1, cidr=2: CIDR{ip=1, prefix=2}}}
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


def write_geoip(path, code, nets):
    entry = _field(1, code.upper().encode())
    for n in nets:
        entry += _field(2, _field(1, n.network_address.packed) + _varint(2 << 3) + _varint(n.prefixlen))
    open(path, "wb").write(_field(1, entry))


def main():
    (ru_rules_path, extra_path, never_path, inside_path, blocked_path, claude_path, provider_path,
     out_path, server_dir, *blocklists) = sys.argv[1:]

    claude_suffix, claude_exact, claude_nets = read_route(claude_path)
    provider = read_list(provider_path)

    def taken(d):  # decided by the first two sections; left out of the later ones
        return d in claude_exact or under(d, claude_suffix | provider)

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

    # Blocked in Russia but would otherwise go direct -> Auto (inside-only always wins)
    proxy_exc = minimal([d for d in read_list(blocked_path) if goes_direct(d) and not under(d, inside)]
                        + sorted(never))
    proxy_exc = [d for d in proxy_exc if not taken(d)]

    reject = set()
    for path in blocklists:
        reject |= {d for d in read_list(path) if goes_direct(d)}
    reject = [d for d in minimal(reject) if d not in direct_suffix and d not in inside and not taken(d)]

    names = (CLAUDE_NODE, *OLD_NODES)
    assert all(re.fullmatch(r"[A-Za-z0-9_-]+", n) for n in names), "server names must need no regex escaping"
    auto_regex = "^(?!(?:" + "|".join(names) + ")$).*$"
    lines = [GENERAL.format(date=datetime.date.today().isoformat(), update_url=os.environ["UPDATE_URL"],
                            claude=CLAUDE, claude_node=CLAUDE_NODE, auto=AUTO, auto_regex=auto_regex,
                            auto_url=AUTO_TEST_URL)]
    lines.append(f"# 1. Claude and Anthropic, only through the Claude server (claude-route.txt): "
                 f"{len(claude_suffix)} domains, {len(claude_exact)} hosts, {len(claude_nets)} address ranges")
    lines += [f"DOMAIN-SUFFIX,{d},{CLAUDE}" for d in sorted(claude_suffix)]
    lines += [f"DOMAIN,{d},{CLAUDE}" for d in sorted(claude_exact)]
    lines += [f"IP-CIDR{'6' if n.version == 6 else ''},{n},{CLAUDE},no-resolve" for n in claude_nets]
    lines += ["", "# 2. The VPN provider's subscription server, over the normal connection (provider-direct.txt)"]
    lines += [f"DOMAIN-SUFFIX,{d},DIRECT" for d in sorted(provider)]
    lines += ["", f"# 3. Russian ad, tracker and malware domains (HaGeZi Pro + Threat Intel): {len(reject)}"]
    lines += [f"DOMAIN-SUFFIX,{d},REJECT" for d in reject]
    lines += ["", "# 4. Local network"]
    lines += [f"IP-CIDR,{n},DIRECT,no-resolve" for n in
              ("192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12", "127.0.0.0/8", "169.254.0.0/16")]
    lines += ["", f"# 5. Russian services that only work from inside Russia (runetfreedom): {len(inside)}"]
    lines += [f"DOMAIN-SUFFIX,{d},DIRECT" for d in sorted(inside) if not taken(d)]
    lines += ["", f"# 6. Russian sites that Russia blocks (runetfreedom ru-blocked), and non-Russian sites the\n"
                  f"#    Russian lists include by mistake: {len(proxy_exc)}"]
    lines += [f"DOMAIN-SUFFIX,{d},{AUTO}" for d in proxy_exc]
    lines += ["", "# 7. Russian top-level domains"]
    lines += [f"DOMAIN-SUFFIX,{t},DIRECT" for t in RU_TLDS]
    lines += ["", "# 8. Russian services on other domains (v2fly category-ru, plus extras)"]
    lines += [f"DOMAIN-SUFFIX,{d},DIRECT" for d in sorted(extra) if not taken(d)]
    lines += [f"DOMAIN-SUFFIX,{d},DIRECT" for d in sorted(cat_suffix - extra) if not taken(d)]
    lines += [f"DOMAIN,{d},DIRECT" for d in sorted(cat_exact) if not taken(d)]
    lines += ["", "# 9. Connections an app makes straight to a Russian IP (no DNS lookup is triggered)",
              "GEOIP,RU,DIRECT,no-resolve", "", "# 10. Everything else: the VPN", f"FINAL,{AUTO}"]
    open(out_path, "w").write("\n".join(lines) + "\n")

    os.makedirs(server_dir, exist_ok=True)
    write_geosite(os.path.join(server_dir, "client-claude.dat"), "claude", claude_suffix, claude_exact)
    write_geoip(os.path.join(server_dir, "client-claude-ip.dat"), "claude", claude_nets)
    print(f"claude {len(claude_suffix)}+{len(claude_exact)}+{len(claude_nets)}, reject {len(reject)}, "
          f"inside-only {len(inside)}, blocked->auto {len(proxy_exc)}, direct suffixes {len(direct_suffix)}, "
          f"exact {len(cat_exact)}", file=sys.stderr)


main()
