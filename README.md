# shadowrocket-ru-split

A self-updating [Shadowrocket](https://apps.apple.com/app/shadowrocket/id932747118) config for
using a proxy from Russia: Russian sites keep using the normal connection, everything else goes
through the proxy, and Russian sites that Russia blocks go through the proxy too.

Add it in Shadowrocket from this address and turn on Settings → Auto Update:

```
https://raw.githubusercontent.com/82hz4j8b4n-star/shadowrocket-ru-split/dist/shadowrocket.conf
```

## Rules (first match wins)

1. Russian ad, tracker and malware domains ([HaGeZi](https://github.com/hagezi/dns-blocklists) Pro + TIF): REJECT
2. Services that only work from inside Russia ([runetfreedom](https://github.com/runetfreedom/russia-blocked-geosite) `ru-available-only-inside`): DIRECT
3. Russian sites that Russia blocks (runetfreedom `ru-blocked`) and `never-direct.txt`: PROXY
4. `.ru`, `.su`, `.рф`, [v2fly](https://github.com/v2fly/domain-list-community) `category-ru` and `extra-ru-domains.txt`: DIRECT
5. Connections straight to a Russian IP: DIRECT
6. Everything else: PROXY

DNS: proxied names are resolved on the server; direct names use Yandex's encrypted DNS; the
server's own name is looked up abroad (Cloudflare, Google and Quad9 in parallel), so a Russian
resolver can't block it. Nothing falls back to the direct connection if the proxy is down.

## How it updates

The `build` workflow runs daily: it downloads the upstream lists, builds the config, and checks it
(67 named test sites, list sizes, no public TLD sent direct, the world's top 20,000 sites). Only a
build that passes and actually changed is published to the `dist` branch.

`client-direct.dat` / `client-proxy.dat` on `dist` are the same lists in Xray geosite format, for
a server that wants to refuse what clients send direct and accept what they send through.

Local build: `./build.sh` (needs `python3` and `curl`) writes to `~/.cache/shadowrocket-ru-split`.
