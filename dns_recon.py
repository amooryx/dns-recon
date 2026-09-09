import socket, rclib

def run(ctx):
    host = ctx.target
    ctx.info(f"resolving {host}")
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as e:
        ctx.err(f"resolution failed: {e}"); return 1
    v4 = sorted({i[4][0] for i in infos if i[0] == socket.AF_INET})
    v6 = sorted({i[4][0] for i in infos if i[0] == socket.AF_INET6})
    for ip in v4: ctx.good(f"A     {ip}")
    for ip in v6: ctx.good(f"AAAA  {ip}")
    ctx.data["a"] = v4; ctx.data["aaaa"] = v6
    for ip in v4:
        try:
            rev = socket.gethostbyaddr(ip)[0]
            ctx.step(f"PTR {ip} -> {rev}")
        except OSError:
            pass
    try:
        cname = socket.gethostbyname_ex(host)
        if cname[1]:
            ctx.step("aliases: " + ", ".join(cname[1]))
            ctx.data["aliases"] = cname[1]
    except OSError:
        pass
    if not v4 and not v6:
        ctx.warn("no records found")
    return 0

rclib.main("dns-recon", "DNS resolution: A/AAAA/PTR/CNAME", run)
