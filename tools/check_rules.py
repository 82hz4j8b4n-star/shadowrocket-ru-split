"""Check the Shadowrocket config the way Shadowrocket applies it (first matching rule wins).

usage: python3 -I check_rules.py <shadowrocket.conf> <inside-only.txt> [<tranco.csv>]
Domain requests only: IP rules marked no-resolve are skipped for them, as in Shadowrocket.
Exits non-zero (so nothing gets published) if any named test domain is classified wrong, a
list is suspiciously small, a whole public TLD would go direct, or too many popular non-Russian
sites would go direct (all signs of a broken or tampered upstream list).
"""
import sys

conf, inside_path, *rest = sys.argv[1:]

rules = []
in_rules = False
for line in open(conf, encoding="utf-8"):
    line = line.strip()
    if line.startswith("["):
        in_rules = line == "[Rule]"
        continue
    if not in_rules or not line or line.startswith("#"):
        continue
    parts = line.split(",")
    rules.append(parts)

suffix_rules = {}  # domain -> (index, policy)
exact_rules = {}
other = []
for i, p in enumerate(rules):
    kind = p[0]
    if kind == "DOMAIN-SUFFIX":
        suffix_rules.setdefault(p[1], (i, p[2]))
    elif kind == "DOMAIN":
        exact_rules.setdefault(p[1], (i, p[2]))
    elif kind == "FINAL":
        final = (i, p[1])
    elif kind == "DOMAIN-KEYWORD":
        other.append((i, p))
    # IP-CIDR/GEOIP with no-resolve never match a domain request
    elif kind in ("IP-CIDR", "GEOIP") and "no-resolve" not in p:
        raise SystemExit(f"rule without no-resolve would trigger a local DNS lookup: {','.join(p)}")


# --- guards against broken or tampered upstream lists
RU_TLDS_OK = {"ru", "su", "xn--p1ai", "moscow", "tatar", "yandex", "xn--80adxhks", "xn--80asehdb",
              "xn--80aswg", "xn--c1avg", "xn--d1acj3b", "xn--p1acf"}
problems = []
by_policy = {}
for dom, (_, pol) in suffix_rules.items():
    by_policy[pol] = by_policy.get(pol, 0) + 1
    if pol == "DIRECT" and "." not in dom and dom not in RU_TLDS_OK:
        problems.append(f"a whole TLD would go DIRECT: .{dom}")
for pol, minimum in (("REJECT", 1000), ("DIRECT", 500), ("PROXY", 5000)):
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


inside = {l.split(":", 1)[1].strip() for l in open(inside_path) if l.strip()}

cases = {
    "REJECT": ["mc.yandex.ru", "an.yandex.ru", "ads.vk.com", "ad.mail.ru", "top-fwz1.mail.ru"],
    "DIRECT": ["gosuslugi.ru", "esia.gosuslugi.ru", "ozon.ru", "yandex.net", "ozonusercontent.com",
               "rzd.ru", "pochta.ru", "ya.ru", "vk.com", "m.vk.com", "sun9-1.userapi.com", "mail.ru",
               "sberbank.com", "online.sberbank.ru", "wildberries.ru", "avito.ru", "2gis.com", "max.ru",
               "xn--80aswg.xn--p1ai", "kinopoisk.ru", "tbank.ru", "hh.ru", "dzen.ru", "rutube.ru"],
    "PROXY": ["tvrain.ru", "novayagazeta.ru", "theins.ru", "habr.com", "rutracker.ru", "meduza.io",
              "google.com", "www.youtube.com", "rr1.googlevideo.com", "instagram.com", "scontent.cdninstagram.com",
              "facebook.com", "web.whatsapp.com", "telegram.org", "t.me", "x.com", "wikipedia.org",
              "chatgpt.com", "apple.com", "icloud.com", "netflix.com", "discord.com", "linkedin.com",
              "signal.org", "proton.me", "github.com", "dns.google", "cloudflare.com",
              # Claude must never go direct (it refuses Russian addresses)
              "claude.ai", "api.anthropic.com", "anthropic.com", "claude.com",
              "claudeusercontent.com", "statsig.anthropic.com", "clau.de", "hcaptcha.com",
              "js.stripe.com", "m.stripe.network"],
}
bad = 0
for want, ds in cases.items():
    for d in ds:
        got = decide(d)
        if got != want:
            bad += 1
            print(f"  WRONG {d}: expected {want}, got {got}")
print(f"named test domains: {sum(map(len, cases.values()))} checked, {bad} wrong")
problems += [f"{bad} named test domain(s) classified wrong"] if bad else []

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
