"""List categories in a v2ray/xray geosite.dat, or dump one category.

usage: python3 -I geosite_dump.py <geosite.dat>            -> category names and sizes
       python3 -I geosite_dump.py <geosite.dat> <category> -> one "type:value" per line
types: plain (keyword), regexp, domain (domain + subdomains), full
"""
import sys

TYPES = {0: "keyword", 1: "regexp", 2: "domain", 3: "full"}


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
            raise ValueError(wt)
        yield num, v


def main():
    data = memoryview(open(sys.argv[1], "rb").read())
    want = sys.argv[2].lower() if len(sys.argv) > 2 else None
    for num, site in fields(data):
        if num != 1:
            continue
        code, domains = None, []
        for n, v in fields(site):
            if n == 1:
                code = bytes(v).decode().lower()
                if want and code != want:
                    break
            elif n == 2:
                if want is None:
                    domains.append(None)
                    continue
                t, val = 0, ""
                for m, w in fields(v):
                    if m == 1:
                        t = w
                    elif m == 2:
                        val = bytes(w).decode()
                domains.append(f"{TYPES.get(t, t)}:{val}")
        if want is None:
            print(f"{code}\t{len(domains)}")
        elif code == want:
            print("\n".join(domains))
            return


main()
