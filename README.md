# shadowrocket-ru-split

A self-updating [Shadowrocket](https://apps.apple.com/app/shadowrocket/id932747118) config for
using the internet from Russia with two servers: Claude and Anthropic go only through a dedicated
Claude server, Russian sites keep using the normal connection, and everything else goes through
the fastest server of a VPN subscription.

Add it in Shadowrocket from this address and turn on Settings → Auto Update:

```
https://raw.githubusercontent.com/82hz4j8b4n-star/shadowrocket-ru-split/dist/shadowrocket.conf
```

It expects two things on the Shadowrocket home screen: the Claude server, named `Claude-DE`, and
the VPN subscription. Global Routing must be **Config** (the Proxy mode ignores groups).

## Groups

- **Claude**: only the server named `Claude-DE`. If it is missing or down, Claude fails (REJECT);
  it never goes through the VPN or directly.
- **Auto**: every other server, the fastest one that reaches a site Russia blocks (tested every
  10 minutes against `www.youtube.com/generate_204`), so a server that comes out inside Russia or
  a placeholder entry is never used. Follows the subscription as its servers change.

## Rules (first match wins)

1. Claude and Anthropic ([`claude-route.txt`](claude-route.txt): Anthropic's domains, sign-in and
   payment checks, Anthropic's address ranges): **Claude**
2. The VPN's subscription server ([`provider-direct.txt`](provider-direct.txt)): DIRECT
3. Russian ad, tracker and malware domains ([HaGeZi](https://github.com/hagezi/dns-blocklists) Pro + TIF): REJECT
4. Services that only work from inside Russia ([runetfreedom](https://github.com/runetfreedom/russia-blocked-geosite) `ru-available-only-inside`): DIRECT
5. Russian sites that Russia blocks (runetfreedom `ru-blocked`) and `never-direct.txt`: **Auto**
6. `.ru`, `.su`, `.рф`, [v2fly](https://github.com/v2fly/domain-list-community) `category-ru` and `extra-ru-domains.txt`: DIRECT
7. Connections straight to a Russian IP: DIRECT
8. Everything else: **Auto**

DNS: names that go through a server are resolved there; direct names use Yandex's encrypted DNS;
the servers' own names use Cloudflare, Google and Quad9 in parallel. Nothing falls back to the
direct connection if a server is down.

## How it updates

The `build` workflow runs daily and on every push: it downloads the upstream lists, builds the
config, and checks it (the groups, that every Claude rule is at the top, 100+ named test sites and
addresses, list sizes, no public TLD sent direct, the world's top 20,000 sites). Only a build that
passes and actually changed is published to the `dist` branch.

`client-claude.dat` / `client-claude-ip.dat` on `dist` are the Claude rules in Xray geosite and
geoip format, so the Claude server accepts exactly what this config sends it and nothing else.

Local build: `./build.sh` (needs `python3`, `curl`).
