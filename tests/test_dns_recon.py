import argparse
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
    @patch.object(dns_recon.socket, "getaddrinfo")
    def test_invalid_input_does_not_resolve(self, getaddrinfo):
        ctx = Context("https://example.com")
        self.assertEqual(dns_recon.run(ctx), 2)
        getaddrinfo.assert_not_called()
        self.assertIn("invalid target", ctx.messages[-1])

    @patch.object(dns_recon.socket, "getaddrinfo", side_effect=socket.gaierror("offline"))
    def test_resolution_error_is_reported(self, getaddrinfo):
        ctx = Context()
        self.assertEqual(dns_recon.run(ctx), 1)
        self.assertIn("resolution failed", ctx.messages[-1])

    @patch.object(dns_recon.socket, "gethostbyaddr")
    @patch.object(dns_recon.socket, "getaddrinfo", return_value=[(socket.AF_INET,)])
    def test_malformed_resolver_response_is_reported(self, getaddrinfo, gethostbyaddr):
        ctx = Context(ptr=True)
        self.assertEqual(dns_recon.run(ctx), 1)
        self.assertIn("invalid resolver response", ctx.messages[-1])
        gethostbyaddr.assert_not_called()

    def test_resolver_address_family_mismatch_is_rejected(self):
        malformed = [addrinfo(socket.AF_INET, "2001:db8::1")]
        with self.assertRaisesRegex(ValueError, "address-family mismatch"):
            dns_recon.parse_resolver_results(malformed)

    @patch.object(dns_recon.socket, "getaddrinfo")
    def test_records_are_deduplicated_and_labeled_as_resolver_observations(self, getaddrinfo):
        getaddrinfo.return_value = [
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

    @patch.object(dns_recon.socket, "gethostbyaddr", return_value=("ptr.example", [], []))
    @patch.object(dns_recon.socket, "getaddrinfo")
    def test_ptr_is_opt_in_and_capped(self, getaddrinfo, gethostbyaddr):
        getaddrinfo.return_value = [
            addrinfo(socket.AF_INET, f"192.0.2.{index}")
            for index in range(1, dns_recon.MAX_PTR_LOOKUPS + 3)
        ]
        ctx = Context(ptr=True)
        self.assertEqual(dns_recon.run(ctx), 0)
        self.assertEqual(gethostbyaddr.call_count, dns_recon.MAX_PTR_LOOKUPS)
        self.assertEqual(len(ctx.data["ptr_observations"]), dns_recon.MAX_PTR_LOOKUPS)
        self.assertTrue(any("PTR lookups capped" in message for message in ctx.messages))

    @patch.object(dns_recon.socket, "gethostbyaddr", side_effect=socket.herror("no PTR"))
    @patch.object(dns_recon.socket, "getaddrinfo")
    def test_ptr_errors_are_reported_and_preserved(self, getaddrinfo, gethostbyaddr):
        getaddrinfo.return_value = [addrinfo(socket.AF_INET, "192.0.2.1")]
        ctx = Context(ptr=True)
        self.assertEqual(dns_recon.run(ctx), 0)
        self.assertEqual(ctx.data["ptr_errors"], {"192.0.2.1": "no PTR"})
        self.assertTrue(any("PTR lookup failed" in message for message in ctx.messages))


if __name__ == "__main__":
    unittest.main()
