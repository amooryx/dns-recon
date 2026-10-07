import argparse
import multiprocessing
import socket
import unittest
from unittest.mock import patch

import dns_recon


class Context:
    def __init__(self, target="example.com", ptr=False):
        self.target = target
        self.args = argparse.Namespace(ptr=ptr)
        self.data = {}
        self.messages = []

    def info(self, message):
        self.messages.append(message)

    def good(self, message):
        self.messages.append(message)

    def warn(self, message):
        self.messages.append(message)

    def err(self, message):
        self.messages.append(message)

    def step(self, message):
        self.messages.append(message)


def addrinfo(family, address):
    sockaddr = (address, 0) if family == socket.AF_INET else (address, 0, 0, 0)
    return family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", sockaddr


class NormalizeHostTests(unittest.TestCase):
    def test_normalizes_idna_and_fqdn(self):
        self.assertEqual(dns_recon.normalize_host("Bücher.Example."), "xn--bcher-kva.example.")

    def test_accepts_ip_literals(self):
        self.assertEqual(dns_recon.normalize_host("2001:db8::1"), "2001:db8::1")

    def test_rejects_urls_whitespace_and_malformed_labels(self):
        for target in ("https://example.com", "example.com/path", "bad host", "-bad.example", "999.1.1.1"):
            with self.subTest(target=target), self.assertRaises(ValueError):
                dns_recon.normalize_host(target)


class RunTests(unittest.TestCase):
    @patch.object(dns_recon, "_query_in_worker")
    def test_invalid_input_does_not_resolve(self, query):
        ctx = Context("https://example.com")
        self.assertEqual(dns_recon.run(ctx), 2)
        query.assert_not_called()
        self.assertIn("invalid target", ctx.messages[-1])

    @patch.object(dns_recon, "_query_in_worker", side_effect=OSError("offline"))
    def test_resolution_error_is_reported(self, query):
        ctx = Context()
        self.assertEqual(dns_recon.run(ctx), 1)
        self.assertIn("resolution failed", ctx.messages[-1])

    @patch.object(dns_recon, "_query_in_worker", return_value=[(socket.AF_INET,)])
    def test_malformed_resolver_response_is_reported(self, query):
        ctx = Context(ptr=True)
        self.assertEqual(dns_recon.run(ctx), 1)
        self.assertIn("invalid resolver response", ctx.messages[-1])
        query.assert_called_once_with("addresses", "example.com")

    def test_resolver_address_family_mismatch_is_rejected(self):
        malformed = [addrinfo(socket.AF_INET, "2001:db8::1")]
        with self.assertRaisesRegex(ValueError, "address-family mismatch"):
            dns_recon.parse_resolver_results(malformed)

    @patch.object(dns_recon, "_query_in_worker")
    def test_records_are_deduplicated_and_labeled_as_resolver_observations(self, query):
        query.return_value = [
            addrinfo(socket.AF_INET, "192.0.2.1"),
            addrinfo(socket.AF_INET, "192.0.2.1"),
            addrinfo(socket.AF_INET6, "2001:db8::1"),
        ]
        ctx = Context()
        self.assertEqual(dns_recon.run(ctx), 0)
        self.assertEqual(
            ctx.data["resolver_observations"],
            {
                "ipv4": ["192.0.2.1"],
                "ipv6": ["2001:db8::1"],
                "source": "system resolver (not an authoritative DNS RRset)",
            },
        )

    @patch.object(dns_recon.time, "sleep")
    @patch.object(dns_recon, "_query_in_worker")
    def test_ptr_is_opt_in_and_capped(self, query, sleep):
        addresses = [
            addrinfo(socket.AF_INET, f"192.0.2.{index}")
            for index in range(1, dns_recon.MAX_PTR_LOOKUPS + 3)
        ]

        def resolve(operation, value):
            if operation == "addresses":
                return addresses
            return "ptr.example", [], []

        query.side_effect = resolve
        ctx = Context(ptr=True)
        self.assertEqual(dns_recon.run(ctx), 0)
        self.assertEqual(
            sum(call.args[0] == "ptr" for call in query.call_args_list),
            dns_recon.MAX_PTR_LOOKUPS,
        )
        self.assertEqual(len(ctx.data["ptr_observations"]), dns_recon.MAX_PTR_LOOKUPS)
        self.assertTrue(any("PTR lookups capped" in message for message in ctx.messages))

    @patch.object(dns_recon.time, "sleep")
    @patch.object(dns_recon, "_query_in_worker")
    def test_ptr_errors_are_reported_and_preserved(self, query, sleep):
        def resolve(operation, value):
            if operation == "addresses":
                return [addrinfo(socket.AF_INET, "192.0.2.1")]
            raise OSError("no PTR")

        query.side_effect = resolve
        ctx = Context(ptr=True)
        self.assertEqual(dns_recon.run(ctx), 0)
        self.assertEqual(ctx.data["ptr_errors"], {"192.0.2.1": "no PTR"})
        self.assertTrue(any("PTR lookup failed" in message for message in ctx.messages))


class WorkerTimeoutTests(unittest.TestCase):
    def test_timed_out_resolver_worker_is_terminated(self):
        class Pipe:
            def __init__(self):
                self.closed = False

            def close(self):
                self.closed = True

            def poll(self, timeout):
                self.timeout = timeout
                return False

        class Process:
            pid = 123

            def __init__(self, **kwargs):
                self.terminated = False

            def start(self):
                pass

            def terminate(self):
                self.terminated = True

            def join(self, timeout=None):
                pass

            def is_alive(self):
                return not self.terminated

        class Context:
            def __init__(self):
                self.parent = Pipe()
                self.child = Pipe()
                self.process = None

            def Pipe(self, duplex):
                return self.parent, self.child

            def Process(self, **kwargs):
                self.process = Process(**kwargs)
                return self.process

        context = Context()
        with (
            patch.object(multiprocessing, "get_context", return_value=context),
            patch.object(dns_recon.time, "monotonic", side_effect=[10.0, 12.0]),
        ):
            with self.assertRaisesRegex(TimeoutError, "exceeded 5 seconds"):
                dns_recon._query_in_worker("addresses", "example.com")

        self.assertEqual(
            context.parent.timeout, dns_recon.RESOLVER_TIMEOUT_SECONDS - 2
        )
        self.assertTrue(context.process.terminated)
        self.assertTrue(context.parent.closed)
        self.assertTrue(context.child.closed)


class ResolverRateLimitTests(unittest.TestCase):
    @patch.object(dns_recon, "_query_in_worker", return_value=[])
    @patch.object(dns_recon.time, "sleep")
    @patch.object(dns_recon.time, "monotonic", side_effect=[0.0, 0.0, 0.1, 0.25])
    def test_waits_to_enforce_minimum_spacing(self, monotonic, sleep, query):
        resolver = dns_recon.ResolverClient()
        resolver.query("addresses", "example.com")
        resolver.query("ptr", "192.0.2.1")

        sleep.assert_called_once_with(dns_recon.MIN_QUERY_INTERVAL_SECONDS - 0.1)
        self.assertEqual(query.call_count, 2)


if __name__ == "__main__":
    unittest.main()
