import io
import ssl
import unittest
from contextlib import redirect_stdout
from unittest import mock

from scanner import (
    DEFAULT_PORTS,
    build_http_request,
    fingerprint_http,
    fingerprint_https,
    guess_service_from_banner,
    parse_http_response,
    parse_ports,
    print_results,
    resolve_target,
    sanitize_terminal,
    scan_port,
    scan_ports,
)


class TestPortParser(unittest.TestCase):
    def test_default_ports(self):
        self.assertEqual(parse_ports(None), DEFAULT_PORTS)
        self.assertIsNot(parse_ports(None), DEFAULT_PORTS)

    def test_single_ports(self):
        self.assertEqual(parse_ports("80,443"), [80, 443])

    def test_port_range(self):
        self.assertEqual(
            parse_ports("8000-8002"),
            [8000, 8001, 8002],
        )

    def test_duplicate_ports_removed(self):
        self.assertEqual(parse_ports("80,80,443"), [80, 443])

    def test_spaces_are_allowed(self):
        self.assertEqual(parse_ports(" 443, 80 "), [80, 443])

    def test_invalid_port(self):
        with self.assertRaises(ValueError):
            parse_ports("70000")

    def test_large_range_is_rejected_before_expansion(self):
        range_mock = mock.Mock()
        with mock.patch("scanner.range", range_mock, create=True):
            with self.assertRaisesRegex(ValueError, "100000000"):
                parse_ports("1-100000000")

        range_mock.assert_not_called()

    def test_reversed_range(self):
        with self.assertRaises(ValueError):
            parse_ports("9000-8000")

    def test_invalid_text(self):
        with self.assertRaises(ValueError):
            parse_ports("http")


class TestHTTPParser(unittest.TestCase):
    def test_status_and_server(self):
        response = (
            b"HTTP/1.1 200 OK\r\n"
            b"Server: nginx/1.24.0\r\n"
            b"Content-Length: 0\r\n"
            b"\r\n"
        )

        result = parse_http_response(response)

        self.assertEqual(result["status_code"], 200)
        self.assertEqual(result["server_header"], "nginx/1.24.0")

    def test_server_header_is_case_insensitive(self):
        result = parse_http_response(
            b"HTTP/1.0 404 Not Found\r\nserver: test-server\r\n\r\n"
        )

        self.assertEqual(result["status_code"], 404)
        self.assertEqual(result["server_header"], "test-server")

    def test_non_http_response(self):
        result = parse_http_response(b"SSH-2.0-OpenSSH_9.6\r\n")

        self.assertIsNone(result["status_code"])
        self.assertIsNone(result["server_header"])

    @mock.patch("scanner._request_http")
    def test_head_not_allowed_falls_back_to_get(self, request_http):
        request_http.side_effect = [
            b"HTTP/1.1 405 Method Not Allowed\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nServer: fallback\r\n\r\n",
        ]

        response = fingerprint_http("example.test", 80, 1.0)

        self.assertEqual(parse_http_response(response)["status_code"], 200)
        self.assertEqual(
            [call.args[3] for call in request_http.call_args_list],
            ["HEAD", "GET"],
        )


class TestHTTPRequest(unittest.TestCase):
    def test_default_http_port_is_not_added_to_host(self):
        request = build_http_request("example.test", port=80)

        self.assertIn(b"\r\nHost: example.test\r\n", request)

    def test_non_default_http_port_is_added_to_host(self):
        request = build_http_request("example.test", port=8080)

        self.assertIn(b"\r\nHost: example.test:8080\r\n", request)

    def test_non_default_https_port_is_added_to_host(self):
        request = build_http_request(
            "example.test",
            port=8443,
            tls=True,
        )

        self.assertIn(b"\r\nHost: example.test:8443\r\n", request)

    def test_ipv6_host_is_bracketed(self):
        request = build_http_request("2001:db8::1", port=8080)

        self.assertIn(b"\r\nHost: [2001:db8::1]:8080\r\n", request)


class TestTLSFingerprint(unittest.TestCase):
    @mock.patch("scanner._fingerprint_https_with_context")
    def test_certificate_failure_uses_unverified_fallback(self, fingerprint):
        fingerprint.side_effect = [
            ssl.SSLCertVerificationError(
                1,
                "certificate verify failed",
            ),
            {"certificate_verified": False},
        ]

        result = fingerprint_https("example.test", 443, 1.0)

        self.assertFalse(result["certificate_verified"])
        self.assertEqual(fingerprint.call_count, 2)
        self.assertTrue(fingerprint.call_args_list[0].kwargs["verified"])
        self.assertFalse(fingerprint.call_args_list[1].kwargs["verified"])


class TestTerminalOutput(unittest.TestCase):
    def test_control_characters_are_escaped(self):
        value = "nginx\x1b[2J\x07\x85banner"

        self.assertEqual(
            sanitize_terminal(value),
            r"nginx\x1b[2J\x07\x85banner",
        )

    def test_sanitized_output_is_limited(self):
        self.assertEqual(sanitize_terminal("abcdef", limit=4), "abcd")

    def test_remote_fields_are_sanitized_before_printing(self):
        results = [
            {
                "port": 80,
                "status": "open",
                "service_guess": "HTTP",
                "banner": {
                    "server_header": "nginx\x1b[2J",
                    "status_code": 200,
                },
            },
            {
                "port": 22,
                "status": "open",
                "service_guess": "SSH",
                "banner": {"raw_banner": "SSH-2.0-test\x07"},
            },
        ]
        output = io.StringIO()

        with redirect_stdout(output):
            print_results("example.test", "now", 0.1, results)

        terminal_text = output.getvalue()
        self.assertNotIn("\x1b", terminal_text)
        self.assertNotIn("\x07", terminal_text)
        self.assertIn(r"nginx\x1b[2J", terminal_text)
        self.assertIn(r"SSH-2.0-test\x07", terminal_text)


class TestTargetResolution(unittest.TestCase):
    @mock.patch("scanner.socket.getaddrinfo")
    def test_ipv6_address_can_be_resolved(self, getaddrinfo):
        getaddrinfo.return_value = [
            (
                10,
                1,
                6,
                "",
                ("2001:db8::10", 0, 0, 0),
            )
        ]

        self.assertEqual(resolve_target("example.test"), "2001:db8::10")


class TestServiceGuess(unittest.TestCase):
    def test_ssh_banner_is_detected(self):
        self.assertEqual(
            guess_service_from_banner("SSH-2.0-OpenSSH_9.6"),
            "SSH",
        )


class TestScanResult(unittest.TestCase):
    @mock.patch("scanner.check_port", return_value="closed")
    def test_closed_port_has_null_banner(self, _check_port):
        result = scan_port("localhost", 12345, 0.1)

        self.assertEqual(result["status"], "closed")
        self.assertIsNone(result["service_guess"])
        self.assertIsNone(result["banner"])

    @mock.patch("scanner.check_port", return_value="closed")
    def test_resolved_address_is_used_for_connection(self, check_port):
        scan_port(
            "example.test",
            443,
            0.1,
            connect_address="192.0.2.10",
        )

        check_port.assert_called_once_with("192.0.2.10", 443, 0.1)


class TestConcurrency(unittest.TestCase):
    @mock.patch("scanner.concurrent.futures.as_completed", return_value=[])
    @mock.patch("scanner.concurrent.futures.ThreadPoolExecutor")
    def test_worker_count_is_limited_to_50(self, executor, _as_completed):
        scan_ports(
            "localhost",
            list(range(1, 101)),
            timeout=0.1,
            workers=100,
        )

        executor.assert_called_once_with(max_workers=50)


if __name__ == "__main__":
    unittest.main()
