"""Check the Shadowrocket config the way Shadowrocket applies it (first matching rule wins).

usage: python3 -I check_rules.py <shadowrocket.conf> <inside-only.txt> <server-dir> [<tranco.csv>]
Domain requests only, except for the Claude address ranges: IP rules marked no-resolve are skipped
for names, as in Shadowrocket. Exits non-zero (so nothing gets published) if a proxy group is wrong,
anything Claude could go another way, a named test domain is classified wrong, a list is
suspiciously small, a whole public TLD would go direct, too many popular non-Russian sites would go
direct (all signs of a broken or tampered upstream list), or the Claude server's lists in
<server-dir> don't match the config's Claude rules.
"""
import ipaddress
import re
import sys

conf, inside_path, server_dir, *rest = sys.argv[1:]
CLAUDE, CLAUDE_NODE, AUTO = "Claude", "Claude-DE", "Auto"

section, rules, groups = None, [], {}
for line in open(conf, encoding="utf-8"):
    line = line.strip()
    if line.startswith("["):
        section = line
        continue
    if not line or line.startswith("#"):
        continue
    if section == "[Rule]":
        rules.append(line.split(","))
    elif section == "[Proxy Group]":
        name, spec = (s.strip() for s in line.split("=", 1))
        kind, *parts = spec.split(",")
        groups[name] = {"type": kind, "members": [p for p in parts if "=" not in p],
                        **dict(p.split("=", 1) for p in parts if "=" in p)}

problems = []
policies = {"DIRECT", "REJECT"} | set(groups)

suffix_rules, exact_rules, ip_rules, other, pols = {}, {}, [], [], []
final = None
for i, p in enumerate(rules):
    kind, pol = p[0], (p[1] if p[0] == "FINAL" else p[2])
    pols.append(pol)
    if pol not in policies:
        problems.append(f"rule {i} uses an undefined policy: {','.join(p)}")
    if kind == "DOMAIN-SUFFIX":
        suffix_rules.setdefault(p[1], (i, pol))
    elif kind == "DOMAIN":
        exact_rules.setdefault(p[1], (i, pol))
    elif kind == "FINAL":
        final = (i, pol)
    elif kind == "DOMAIN-KEYWORD":
        other.append((i, p))
    elif kind in ("IP-CIDR", "IP-CIDR6", "GEOIP"):
        # an IP rule without no-resolve would make every name before it be looked up locally
        if "no-resolve" not in p:
            raise SystemExit(f"rule without no-resolve would trigger a local DNS lookup: {','.join(p)}")
        if kind != "GEOIP":
            ip_rules.append((i, ipaddress.ip_network(p[1]), pol))
    else:
        problems.append(f"rule type this check doesn't understand: {','.join(p)}")
if final is None or final[1] != AUTO:
    problems.append(f"FINAL must be {AUTO}, is {final}")


# --- proxy groups: the Claude group has only the Claude server (and REJECT if that is missing);
# Auto has every other server
c, a = groups.get(CLAUDE, {}), groups.get(AUTO, {})
if (c.get("type"), c.get("members"), c.get("policy-select-name")) != ("select", [CLAUDE_NODE, "REJECT"], CLAUDE_NODE):
    problems.append(f"group {CLAUDE} must be: select,{CLAUDE_NODE},REJECT,policy-select-name={CLAUDE_NODE}; is {c}")
if a.get("type") != "url-test" or a.get("members") or not a.get("url", "").startswith("https://"):
    problems.append(f"group {AUTO} must be a url-test over a filter with an https test URL; is {a}")
else:
    rx = re.compile(a["policy-regex-filter"])
    for name, want in ((CLAUDE_NODE, False), ("Germany", False), ("🇩🇪 Германия 1", True), ("Germany 2", True),
                       ("🇳🇱 Нидерланды", True), ("Лучший Авто Сервер", True), ("Claude-DE 2", True)):
        if bool(rx.search(name)) != want:
            problems.append(f"group {AUTO}'s filter {'drops' if want else 'takes'} the server {name!r}")
    # the Claude server answers www.gstatic.com (Shadowrocket's own connectivity test), so Auto must test
    # something else, or the Claude server could pass Auto's test
    if re.match(r"https://(www\.gstatic\.com|[^/]*(claude|anthropic))", a["url"]):
        problems.append(f"group {AUTO} must not test against {a['url']}")
if set(groups) != {CLAUDE, AUTO}:
    problems.append(f"unexpected proxy groups: {sorted(groups)}")

# Claude rules come before everything else, so no later list (ads, Russian, blocked) can override them
claude_idx = [i for i, pol in enumerate(pols) if pol == CLAUDE]
if claude_idx != list(range(len(claude_idx))):
    problems.append("the Claude rules are not all at the top of [Rule]")


# --- guards against broken or tampered upstream lists
RU_TLDS_OK = {"ru", "su", "xn--p1ai", "moscow", "tatar", "yandex", "xn--80adxhks", "xn--80asehdb",
              "xn--80aswg", "xn--c1avg", "xn--d1acj3b", "xn--p1acf"}
by_policy = {}
for dom, (_, pol) in suffix_rules.items():
    by_policy[pol] = by_policy.get(pol, 0) + 1
    if pol == "DIRECT" and "." not in dom and dom not in RU_TLDS_OK:
        problems.append(f"a whole TLD would go DIRECT: .{dom}")
for pol, minimum in (("REJECT", 1000), ("DIRECT", 500), (AUTO, 5000), (CLAUDE, 5)):
    if by_policy.get(pol, 0) < minimum:
        problems.append(f"only {by_policy.get(pol, 0)} {pol} rules (expected at least {minimum})")
print(f"suffix rules by policy: {by_policy}")


def decide(d):
    d = d.lower().rstrip(".")
    best = final
    labels = d.split(".")
    for j in range(len(labels)):
        hit = suffix_rules.get(".".join(labels[j:]))
        if hit and hit[0] < best[0]:
            best = hit
    hit = exact_rules.get(d)
    if hit and hit[0] < best[0]:
        best = hit
    for i, p in other:
        if p[1] in d and i < best[0]:
            best = (i, p[2])
    return best[1]


def decide_ip(ip):
    ip = ipaddress.ip_address(ip)
    hits = [(i, pol) for i, net, pol in ip_rules if ip.version == net.version and ip in net]
    return min(hits)[1] if hits else "(no IP rule)"


cases = {
    CLAUDE: ["claude.ai", "www.claude.ai", "api.claude.ai", "assets.claude.ai", "downloads.claude.ai",
             "a.claude.ai", "anthropic.com", "api.anthropic.com", "assets-proxy.anthropic.com",
             "statsig.anthropic.com", "metrics.anthropic.com", "a-api.anthropic.com", "a-cdn.anthropic.com",
             "s-cdn.anthropic.com", "mcp-proxy.anthropic.com", "status.anthropic.com", "claude.com",
             "platform.claude.com", "sso.claude.com", "code.claude.com", "support.claude.com",
             "releases.claude.com", "gmail.mcp.claude.com", "www.claudeusercontent.com",
             "abc.frame.claudeusercontent.com", "bridge.claudeusercontent.com",
             "sandbox.claudemcpcontent.com", "claude.site", "clau.de", "js.hcaptcha.com",
             "newassets.hcaptcha.com", "js.stripe.com", "api.stripe.com", "m.stripe.network",
             "anthropic.skilljar.com"],
    "DIRECT": ["gosuslugi.ru", "esia.gosuslugi.ru", "ozon.ru", "yandex.net", "ozonusercontent.com",
               "rzd.ru", "pochta.ru", "ya.ru", "vk.com", "m.vk.com", "sun9-1.userapi.com", "mail.ru",
               "sberbank.com", "online.sberbank.ru", "wildberries.ru", "avito.ru", "2gis.com", "max.ru",
               "xn--80aswg.xn--p1ai", "kinopoisk.ru", "tbank.ru", "hh.ru", "dzen.ru", "rutube.ru",
               "sub.conn-liberty.net"],
    "REJECT": ["mc.yandex.ru", "an.yandex.ru", "ads.vk.com", "ad.mail.ru", "top-fwz1.mail.ru"],
    AUTO: ["tvrain.ru", "novayagazeta.ru", "theins.ru", "habr.com", "rutracker.ru", "meduza.io",
           "google.com", "www.youtube.com", "rr1.googlevideo.com", "instagram.com", "scontent.cdninstagram.com",
           "facebook.com", "web.whatsapp.com", "telegram.org", "t.me", "x.com", "wikipedia.org",
           "chatgpt.com", "apple.com", "icloud.com", "netflix.com", "discord.com", "linkedin.com",
           "signal.org", "proton.me", "github.com", "dns.google", "cloudflare.com",
           # look-alikes of Claude and shared hosts that stay off the Claude server
           "claude-billing.com", "anthropicipo.net", "claudehub.click", "myclaude.ai.example.net",
           "skilljar.com", "turbovote.org", "fonts.googleapis.com", "cdnjs.cloudflare.com",
           "storage.googleapis.com", "browser-intake-us5-datadoghq.com", "accounts.google.com"],
}
bad = 0
for want, ds in cases.items():
    for d in ds:
        got = decide(d)
        if got != want:
            bad += 1
            print(f"  WRONG {d}: expected {want}, got {got}")
for ip, want in (("160.79.104.10", CLAUDE), ("160.79.111.1", CLAUDE), ("2607:6bc0::10", CLAUDE),
                 ("2607:6bc0:11::1", CLAUDE), ("192.168.2.1", "DIRECT"), ("160.79.112.1", "(no IP rule)")):
    if decide_ip(ip) != want:
        bad += 1
        print(f"  WRONG {ip}: expected {want}, got {decide_ip(ip)}")
print(f"named test domains and addresses: {sum(map(len, cases.values())) + 6} checked, {bad} wrong")
problems += [f"{bad} named test domain(s) classified wrong"] if bad else []


# --- the Claude server's lists must be exactly the config's Claude rules
def read_varint(b, i):
    n = s = 0
    while True:
        n |= (b[i] & 0x7F) << s; s += 7; i += 1
        if b[i - 1] < 0x80:
            return n, i


def fields(b):
    i = 0
    while i < len(b):
        tag, i = read_varint(b, i)
        if tag & 7 == 2:
            n, i = read_varint(b, i)
            yield tag >> 3, b[i:i + n]; i += n
        else:
            v, i = read_varint(b, i)
            yield tag >> 3, v


def dat_entries(path):
    (_, entry), = fields(open(path, "rb").read())
    return [v for f, v in fields(entry) if f == 2]


sites = {(dict(fields(d))[1], dict(fields(d))[2].decode()) for d in dat_entries(f"{server_dir}/client-claude.dat")}
nets = set()
for c in dat_entries(f"{server_dir}/client-claude-ip.dat"):
    f = dict(fields(c))
    nets.add(ipaddress.ip_network((ipaddress.ip_address(f[1]), f[2])))
want_sites = {(2, d) for d, (_, pol) in suffix_rules.items() if pol == CLAUDE} | \
             {(3, d) for d, (_, pol) in exact_rules.items() if pol == CLAUDE}
want_nets = {net for _, net, pol in ip_rules if pol == CLAUDE}
if sites != want_sites or nets != want_nets:
    problems.append(f"server lists differ from the config's Claude rules: sites {sites ^ want_sites}, "
                    f"ranges {nets ^ want_nets}")
print(f"Claude server lists: {len(sites)} names, {len(nets)} ranges, "
      f"{'same as the config' if sites == want_sites and nets == want_nets else 'DIFFERENT'}")

if rest:
    import collections
    ru_tld = ("ru", "su", "xn--p1ai")
    counts = collections.Counter()
    direct_foreign = []
    for n, line in enumerate(open(rest[0])):
        if n >= 20000:
            break
        d = line.strip().split(",")[-1]
        pol = decide(d)
        counts[pol] += 1
        if pol == "DIRECT" and d.rsplit(".", 1)[-1] not in ru_tld:
            direct_foreign.append(d)
    print(f"top 20000 sites: {dict(counts)}")
    print(f"DIRECT but not under .ru/.su/.рф ({len(direct_foreign)}): {' '.join(direct_foreign)}")
    if len(direct_foreign) > 250:
        problems.append(f"{len(direct_foreign)} popular non-Russian-TLD sites would go DIRECT (max 250)")

if problems:
    print("FAILED:\n  " + "\n  ".join(problems))
    sys.exit(1)
print("all checks passed")
