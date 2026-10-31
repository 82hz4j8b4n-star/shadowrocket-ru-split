"""Check which addresses a v2ray/xray geoip.dat puts in a country.

usage: python3 -I geoip_check.py <geoip.dat> <CC> <ip> [<ip> ...]
Prints the number of networks for the country and, per IP, whether it is inside.
"""
import ipaddress
import sys


def varint(b, i):
    shift = n = 0
    while True:
        c = b[i]; i += 1
        n |= (c & 0x7F) << shift
        if c < 0x80:
            return n, i
        shift += 7


def fields(b):
    i = 0
    while i < len(b):
        key, i = varint(b, i)
        num, wt = key >> 3, key & 7
        if wt == 0:
            v, i = varint(b, i)
        elif wt == 2:
            ln, i = varint(b, i)
            v = b[i:i + ln]; i += ln
        elif wt == 5:
            v = b[i:i + 4]; i += 4
        elif wt == 1:
            v = b[i:i + 8]; i += 8
        else:
            raise ValueError(f"wire type {wt}")
        yield num, v


def networks(path, cc):
    data = open(path, "rb").read()
    for num, entry in fields(data):  # GeoIPList.entry = 1
        if num != 1:
            continue
        code, cidrs = None, []
        for n, v in fields(entry):
            if n == 1:
                code = v.decode()
            elif n == 2:
                ip = prefix = None
                for m, w in fields(v):
                    if m == 1:
                        ip = ipaddress.ip_address(bytes(w))
                    elif m == 2:
                        prefix = w
                cidrs.append(ipaddress.ip_network(f"{ip}/{prefix or 0}", strict=False))
        if code and code.lower() == cc.lower():
            return cidrs
    return []


path, cc, *ips = sys.argv[1:]
nets = networks(path, cc)
print(f"{path.rsplit('/', 1)[-1]}: {cc} has {len(nets)} networks")
for ip in ips:
    a = ipaddress.ip_address(ip)
    hit = next((n for n in nets if n.version == a.version and a in n), None)
    print(f"  {ip:18} {'IN ' + str(hit) if hit else 'not in list'}")
