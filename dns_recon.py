#!/usr/bin/env python3
"""
DNS Recon — Comprehensive DNS Reconnaissance Tool
Enumerates DNS records, attempts zone transfers, and performs reverse lookups.
Author: Omar Khalid (amooryx) | github.com/amooryx/dns-recon
AUTHORIZED USE ONLY.
"""

import argparse
import json
import socket
import struct
import sys
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

DOH_URL = "https://8.8.8.8/resolve"
RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "SRV", "PTR", "CAA"]

def doh_query(name: str, rtype: str) -> list[dict]:
    url    = f"{DOH_URL}?name={urllib.parse.quote(name)}&type={urllib.parse.quote(rtype)}"
    req    = urllib.request.Request(url, headers={"Accept": "application/dns-json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
            return data.get("Answer", []) or data.get("Authority", [])
    except Exception:
        return []

def enumerate_records(domain: str) -> dict:
    results = {}
    for rtype in RECORD_TYPES:
        answers = doh_query(domain, rtype)
        if answers:
            results[rtype] = [{"name": a.get("name"), "data": a.get("data"), "ttl": a.get("TTL")}
                              for a in answers]
    return results

def attempt_zone_transfer(domain: str, nameservers: list[str]) -> dict:
    """Attempt AXFR zone transfer against each nameserver."""
    results = {}
    for ns in nameservers:
        try:
            ns_ip = socket.gethostbyname(ns.rstrip("."))
            # Send raw AXFR DNS query via TCP
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((ns_ip, 53))
            # Build minimal AXFR query
            qname = b"".join(len(p).to_bytes(1, "big") + p.encode()
                             for p in domain.split(".")) + b"\x00"
            query = (b"\x00\x01"   # ID
                     b"\x00\x00"   # Flags (standard query)
                     b"\x00\x01"   # QDCOUNT=1
                     b"\x00\x00\x00\x00\x00\x00"  # other counts
                     + qname
                     + b"\x00\xfc"  # QTYPE=AXFR (252)
                     + b"\x00\x01") # QCLASS=IN
            length_prefixed = struct.pack("!H", len(query)) + query
            sock.sendall(length_prefixed)
            raw = sock.recv(4096)
            sock.close()
            if len(raw) > 12:
                rcode = raw[3] & 0x0F  # RCODE in TCP response
                if rcode == 0 and len(raw) > 50:
                    results[ns] = {"success": True, "bytes": len(raw),
                                   "note": "Zone transfer accepted! Enumerate further with dig AXFR."}
                else:
                    results[ns] = {"success": False, "rcode": rcode}
            else:
                results[ns] = {"success": False, "note": "Empty response"}
        except Exception as e:
            results[ns] = {"success": False, "error": str(e)}
    return results

def reverse_lookup_range(cidr_prefix: str, limit: int = 254) -> list[dict]:
    """Reverse DNS lookup for IPs in a /24 range."""
    results = []
    parts = cidr_prefix.split(".")
    if len(parts) < 3:
        return []
    prefix = ".".join(parts[:3])
    def lookup(ip: str) -> dict | None:
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return {"ip": ip, "hostname": hostname}
        except Exception:
            return None
    with ThreadPoolExecutor(max_workers=50) as exe:
        futures = {exe.submit(lookup, f"{prefix}.{i}"): i for i in range(1, limit + 1)}
        for fut in futures:
            r = fut.result()
            if r:
                results.append(r)
    return results

def find_mail_security(domain: str) -> dict:
    """Check SPF, DKIM, and DMARC records."""
    checks = {}
    # SPF
    txt_records = doh_query(domain, "TXT")
    spf = [r["data"] for r in txt_records if "v=spf1" in r.get("data", "").lower()]
    checks["spf"] = spf[0] if spf else "MISSING"

    # DMARC
    dmarc = doh_query(f"_dmarc.{domain}", "TXT")
    checks["dmarc"] = dmarc[0]["data"] if dmarc else "MISSING"

    # DKIM (check common selectors)
    for sel in ["default", "google", "mail", "k1", "s1", "dkim"]:
        dkim = doh_query(f"{sel}._domainkey.{domain}", "TXT")
        if dkim:
            checks[f"dkim_{sel}"] = dkim[0]["data"]
            break
    else:
        checks["dkim"] = "Not found for common selectors"

    return checks

def main():
    parser = argparse.ArgumentParser(
        description="DNS Recon — DNS Reconnaissance Tool (Authorized use only)",
    )
    parser.add_argument("domain",      help="Target domain")
    parser.add_argument("--all", "-a", action="store_true", help="Run all checks")
    parser.add_argument("--records",   action="store_true", help="Enumerate DNS records")
    parser.add_argument("--axfr",      action="store_true", help="Attempt zone transfers")
    parser.add_argument("--reverse",   help="Reverse lookup range prefix (e.g., 192.168.1)")
    parser.add_argument("--mail",      action="store_true", help="Check mail security (SPF/DKIM/DMARC)")
    parser.add_argument("--out",       help="Output JSON file")
    args = parser.parse_args()

    results = {"domain": args.domain}

    if args.records or args.all:
        print(f"[*] Enumerating DNS records for {args.domain} ...")
        records = enumerate_records(args.domain)
        results["records"] = records
        for rtype, answers in records.items():
            for a in answers:
                print(f"  {rtype:6s} {a['name']:<40s} {a['data']}")

    if args.axfr or args.all:
        ns_answers = doh_query(args.domain, "NS")
        nameservers = [a["data"] for a in ns_answers]
        print(f"[*] Attempting zone transfer against {len(nameservers)} NS: {nameservers}")
        axfr = attempt_zone_transfer(args.domain, nameservers)
        results["zone_transfer"] = axfr
        for ns, r in axfr.items():
            flag = "[!!!]" if r.get("success") else "[OK] "
            print(f"  {flag} {ns}: {r.get('note', r.get('error', 'refused'))}")

    if args.reverse:
        print(f"[*] Reverse lookup for {args.reverse}.0/24 ...")
        rev = reverse_lookup_range(args.reverse)
        results["reverse"] = rev
        print(f"  [+] {len(rev)} PTR records found")
        for r in rev[:20]:
            print(f"    {r['ip']:15s} → {r['hostname']}")

    if args.mail or args.all:
        print(f"[*] Mail security check for {args.domain} ...")
        mail = find_mail_security(args.domain)
        results["mail_security"] = mail
        for k, v in mail.items():
            flag = "[MISSING!]" if v == "MISSING" else "[OK]     "
            print(f"  {flag} {k}: {str(v)[:80]}")

    if args.out:
        with open(args.out, "w") as f:
            json.dump(results, f, indent=2)
        print(f"[*] Results → {args.out}")

if __name__ == "__main__":
    main()
