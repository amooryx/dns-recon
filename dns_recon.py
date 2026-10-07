import ipaddress
import multiprocessing
import re
import socket
import time

import rclib


MAX_PTR_LOOKUPS = 10
RESOLVER_TIMEOUT_SECONDS = 5
MIN_QUERY_INTERVAL_SECONDS = 0.25
_LABEL = re.compile(r"(?!-)[a-z0-9-]{1,63}(?<!-)\Z")


def normalize_host(value):
    """Validate a single host/IP target and return an ASCII resolver name."""
    if not value or value != value.strip() or any(ch.isspace() for ch in value):
        raise ValueError("target must be a hostname or IP address without whitespace")

    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass

    candidate = value[:-1] if value.endswith(".") else value
    if not candidate or len(candidate) > 253:
        raise ValueError("hostname must contain between 1 and 253 characters")
    if re.fullmatch(r"[0-9.]+", candidate):
        raise ValueError("invalid IP address")

    try:
        ascii_host = candidate.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError(f"invalid internationalized hostname: {exc}") from exc
    labels = ascii_host.split(".")
    if any(not _LABEL.fullmatch(label) for label in labels):
        raise ValueError("hostname contains an invalid label")
    if len(ascii_host) > 253:
        raise ValueError("hostname must contain at most 253 ASCII characters")
    return ascii_host + ("." if value.endswith(".") else "")


def add_arguments(parser):
    parser.add_argument(
        "--ptr",
        action="store_true",
        help=f"also query PTR for up to {MAX_PTR_LOOKUPS} returned addresses",
    )


def _resolver_worker(connection, operation, value):
    try:
        if operation == "addresses":
            result = socket.getaddrinfo(
                value, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM
            )
        elif operation == "ptr":
            result = socket.gethostbyaddr(value)
        else:
            raise ValueError("unknown resolver operation")
        connection.send(("ok", result))
    except OSError as exc:
        connection.send(("error", type(exc).__name__, str(exc)))
    finally:
        connection.close()


def _query_in_worker(operation, value):
    context = multiprocessing.get_context("spawn")
    parent, child = context.Pipe(duplex=False)
    process = context.Process(target=_resolver_worker, args=(child, operation, value))
    deadline = time.monotonic() + RESOLVER_TIMEOUT_SECONDS
    try:
        process.start()
        child.close()
        remaining = max(0, deadline - time.monotonic())
        if not parent.poll(remaining):
            process.terminate()
            process.join()
            raise TimeoutError(
                f"{operation} lookup exceeded {RESOLVER_TIMEOUT_SECONDS} seconds"
            )
        try:
            message = parent.recv()
        except EOFError as exc:
            raise OSError("resolver worker exited without a result") from exc
        process.join(timeout=0.2)
        if process.is_alive():
            process.terminate()
            process.join()
        if not isinstance(message, tuple) or not message:
            raise OSError("resolver worker returned a malformed response")
        if message[0] == "ok" and len(message) == 2:
            return message[1]
        if message[0] == "error" and len(message) == 3:
            raise OSError(f"{message[1]}: {message[2]}")
        raise OSError("resolver worker returned a malformed response")
    finally:
        parent.close()
        child.close()
        if process.pid is not None:
            if process.is_alive():
                process.terminate()
            process.join()


class ResolverClient:
    def __init__(self):
        self._last_query_started = None

    def query(self, operation, value):
        now = time.monotonic()
        if self._last_query_started is not None:
            delay = MIN_QUERY_INTERVAL_SECONDS - (now - self._last_query_started)
            if delay > 0:
                time.sleep(delay)
        self._last_query_started = time.monotonic()
        return _query_in_worker(operation, value)


def parse_resolver_results(infos):
    """Validate getaddrinfo rows and return deduplicated IPv4/IPv6 literals."""
    if not isinstance(infos, (list, tuple)):
        raise ValueError("resolver returned a malformed result list")

    v4 = set()
    v6 = set()
    for index, item in enumerate(infos, start=1):
        if not isinstance(item, (list, tuple)) or len(item) != 5:
            raise ValueError(f"resolver result {index} has an invalid structure")

        family, _, _, _, sockaddr = item
        if family not in (socket.AF_INET, socket.AF_INET6):
            continue
        if not isinstance(sockaddr, (list, tuple)) or not sockaddr:
            raise ValueError(f"resolver result {index} has an invalid address")
        try:
            parsed_address = ipaddress.ip_address(sockaddr[0])
        except (TypeError, ValueError) as exc:
            raise ValueError(f"resolver result {index} has an invalid IP address") from exc

        expected_version = 4 if family == socket.AF_INET else 6
        if parsed_address.version != expected_version:
            raise ValueError(f"resolver result {index} has an address-family mismatch")
        (v4 if expected_version == 4 else v6).add(str(parsed_address))

    return sorted(v4), sorted(v6)


def run(ctx):
    try:
        host = normalize_host(ctx.target)
    except ValueError as exc:
        ctx.err(f"invalid target: {exc}")
        return 2

    resolver = ResolverClient()
    ctx.info(f"querying the system resolver for {host}")
    try:
        infos = resolver.query("addresses", host)
    except OSError as exc:
        ctx.err(f"resolution failed: {exc}")
        return 1

    try:
        v4, v6 = parse_resolver_results(infos)
    except ValueError as exc:
        ctx.err(f"invalid resolver response: {exc}")
        return 1

    for address in v4:
        ctx.good(f"IPv4 resolver result  {address}")
    for address in v6:
        ctx.good(f"IPv6 resolver result  {address}")

    ctx.data["resolver_observations"] = {
        "ipv4": v4,
        "ipv6": v6,
        "source": "system resolver (not an authoritative DNS RRset)",
    }

    if ctx.args.ptr:
        addresses = v4 + v6
        selected = addresses[:MAX_PTR_LOOKUPS]
        ptr_results = {}
        ptr_errors = {}
        for address in selected:
            try:
                reverse_name = resolver.query("ptr", address)[0]
            except OSError as exc:
                ptr_errors[address] = str(exc)
                ctx.warn(f"PTR lookup failed for {address}: {exc}")
            else:
                ptr_results[address] = reverse_name
                ctx.step(f"PTR resolver result {address} -> {reverse_name}")
        ctx.data["ptr_observations"] = ptr_results
        if ptr_errors:
            ctx.data["ptr_errors"] = ptr_errors
        if len(addresses) > len(selected):
            ctx.warn(
                f"PTR lookups capped at {MAX_PTR_LOOKUPS}; "
                f"{len(addresses) - len(selected)} address(es) not queried"
            )

    if not v4 and not v6:
        ctx.warn("the system resolver returned no IPv4 or IPv6 addresses")
    return 0


if __name__ == "__main__":
    raise SystemExit(
        rclib.main(
            "dns-recon",
            "System-resolver IPv4/IPv6 observations with optional bounded PTR lookups",
            run,
            extra_args=add_arguments,
            target_help="hostname or IP address",
        )
    )
