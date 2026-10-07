<div align="center">
  <img src="./banner.svg" alt="dns-recon" width="800">
</div>

# dns-recon

> A small, user-directed DNS resolver check for authorized testing.

```bash
python dns_recon.py --help
```

The tool asks for authorization before making queries (use `--yes` only when
authorization has already been established). Provide one hostname or IP
address; URLs, paths, and malformed hostnames are rejected. The default
operation makes one system-resolver lookup for IPv4/IPv6 results. These results
reflect the local system resolver and may include hosts-file, cache, or other
NSS data; they are not represented as an authoritative DNS record set or as
confirmed CNAMEs.

Reverse lookups are opt-in and bounded to ten returned addresses:

```bash
python dns_recon.py --ptr example.com
```

Each resolver lookup runs in a worker process with a five-second deadline.
Within one run, lookup starts are spaced at least 250 ms apart. Thus `--ptr`
can issue at most eleven bounded lookups total (one forward lookup and ten
reverse lookups).

JSON output is available with `-o results.json`. PTR lookup failures are
reported rather than silently discarded. No subdomain enumeration or
brute-force queries are performed.

**Omar Khalid** — [omareldemery.com](https://omareldemery.com)
