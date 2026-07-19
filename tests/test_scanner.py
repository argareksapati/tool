import unittest
from unittest import mock

from scanner import (
    DEFAULT_PORTS,
    fingerprint_http,
    parse_http_response,
    parse_ports,
    scan_port,
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


class TestScanResult(unittest.TestCase):
    @mock.patch("scanner.check_port", return_value="closed")
    def test_closed_port_has_null_banner(self, _check_port):
        result = scan_port("localhost", 12345, 0.1)

        self.assertEqual(result["status"], "closed")
        self.assertIsNone(result["service_guess"])
        self.assertIsNone(result["banner"])


if __name__ == "__main__":
    unittest.main()
