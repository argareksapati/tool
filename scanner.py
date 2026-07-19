"""Simple TCP port scanner and lightweight service fingerprinting tool."""

import argparse
import concurrent.futures
import json
import re
import socket
import ssl
import time
from datetime import datetime, timezone


DEFAULT_PORTS = [
    80,
    443,
    8000,
    8080,
    8081,
    8443,
    8888,
    3000,
    5000,
    9000,
]

TLS_PORTS = {
    443,
    8443,
    9443,
}

HTTP_PORTS = {
    80,
    8000,
    8080,
    8081,
    8888,
    3000,
    5000,
    9000,
}

MAX_RESPONSE_BYTES = 8192
MAX_WORKERS = 50
CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def build_parser():
    parser = argparse.ArgumentParser(
        description="Simple Port & Service Fingerprint Tool"
    )

    parser.add_argument(
        "target",
        help="Hostname atau alamat IP yang akan dipindai",
    )
    parser.add_argument(
        "-p",
        "--ports",
        help="Daftar port, contoh: 80,443,8000-8005",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=2.0,
        help="Timeout koneksi dalam detik (default: 2.0)",
    )
    parser.add_argument(
        "-w",
        "--workers",
        type=int,
        default=20,
        help="Jumlah worker concurrent (default: 20, maksimum: 50)",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Simpan hasil lengkap ke file JSON",
    )

    return parser


def parse_ports(value):
    if not value:
        return DEFAULT_PORTS.copy()

    ports = set()

    for item in value.split(","):
        item = item.strip()
        if not item:
            raise ValueError("Daftar port mengandung bagian kosong")

        if "-" in item:
            try:
                start_text, end_text = item.split("-", 1)
                start = int(start_text)
                end = int(end_text)
            except ValueError as error:
                raise ValueError(f"Format port tidak valid: {item}") from error

            if not 1 <= start <= 65535:
                raise ValueError(f"Port tidak valid: {start}")
            if not 1 <= end <= 65535:
                raise ValueError(f"Port tidak valid: {end}")
            if start > end:
                raise ValueError(
                    "Awal range tidak boleh lebih besar dari akhir"
                )

            ports.update(range(start, end + 1))
        else:
            try:
                port = int(item)
            except ValueError as error:
                raise ValueError(f"Format port tidak valid: {item}") from error

            if not 1 <= port <= 65535:
                raise ValueError(f"Port tidak valid: {port}")
            ports.add(port)

    return sorted(ports)


def resolve_target(target):
    addresses = socket.getaddrinfo(
        target,
        None,
        type=socket.SOCK_STREAM,
    )
    if not addresses:
        raise socket.gaierror(f"Target tidak dapat di-resolve: {target}")
    return addresses[0][4][0]


def check_port(target, port, timeout):
    try:
        with socket.create_connection((target, port), timeout=timeout):
            return "open"
    except ConnectionRefusedError:
        return "closed"
    except socket.timeout:
        return "filtered"
    except OSError:
        return "filtered"


def build_http_request(target, method="HEAD", port=None, tls=False):
    default_port = 443 if tls else 80
    host = target

    if ":" in target and not target.startswith("["):
        host = f"[{target}]"

    host_header = host
    if port is not None and port != default_port:
        host_header = f"{host}:{port}"

    request = (
        f"{method} / HTTP/1.1\r\n"
        f"Host: {host_header}\r\n"
        f"User-Agent: SimpleFingerprint/1.0\r\n"
        f"Accept: */*\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    )
    return request.encode("ascii", errors="ignore")


def sanitize_terminal(value, limit=200):
    if value is None:
        return None

    sanitized = CONTROL_CHARS.sub(
        lambda match: f"\\x{ord(match.group()):02x}",
        str(value),
    )
    return sanitized[:limit]


def receive_response(sock, max_bytes=MAX_RESPONSE_BYTES):
    chunks = []
    total = 0

    while total < max_bytes:
        try:
            data = sock.recv(min(2048, max_bytes - total))
        except socket.timeout:
            break

        if not data:
            break

        chunks.append(data)
        total += len(data)

        if b"\r\n\r\n" in b"".join(chunks):
            break

    return b"".join(chunks)


def parse_http_response(response):
    text = response.decode("iso-8859-1", errors="replace")
    header_text = text.split("\r\n\r\n", 1)[0]
    lines = header_text.splitlines()

    status_code = None
    server_header = None

    if lines and lines[0].startswith("HTTP/"):
        parts = lines[0].split()
        if len(parts) >= 2 and parts[1].isdigit():
            status_code = int(parts[1])

    for line in lines[1:]:
        if ":" not in line:
            continue

        name, value = line.split(":", 1)
        if name.strip().lower() == "server":
            server_header = value.strip()

    return {
        "status_code": status_code,
        "server_header": server_header,
        "raw_banner": header_text[:2000],
    }


def _request_http(
    target,
    port,
    timeout,
    method,
    connect_address=None,
):
    address = connect_address or target
    with socket.create_connection((address, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall(
            build_http_request(
                target,
                method=method,
                port=port,
                tls=False,
            )
        )
        return receive_response(sock)


def fingerprint_http(target, port, timeout, connect_address=None):
    response = _request_http(
        target,
        port,
        timeout,
        "HEAD",
        connect_address,
    )
    info = parse_http_response(response)

    if info["status_code"] in (405, 501) or not response:
        response = _request_http(
            target,
            port,
            timeout,
            "GET",
            connect_address,
        )

    return response


def create_unverified_context():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def extract_common_name(certificate):
    for item in certificate.get("subject", ()):
        for key, value in item:
            if key == "commonName":
                return value
    return None


def extract_certificate_expiry(certificate):
    return certificate.get("notAfter")


def normalize_certificate_expiry(value):
    if not value:
        return None

    try:
        parsed = datetime.strptime(value, "%b %d %H:%M:%S %Y %Z")
    except ValueError:
        return value

    return parsed.date().isoformat()


def _request_https_with_context(
    target,
    port,
    timeout,
    context,
    method,
    connect_address=None,
):
    address = connect_address or target
    with socket.create_connection((address, port), timeout=timeout) as raw_sock:
        raw_sock.settimeout(timeout)

        with context.wrap_socket(raw_sock, server_hostname=target) as tls_sock:
            tls_sock.settimeout(timeout)
            certificate = tls_sock.getpeercert()
            tls_version = tls_sock.version()
            cipher = tls_sock.cipher()

            tls_sock.sendall(
                build_http_request(
                    target,
                    method=method,
                    port=port,
                    tls=True,
                )
            )
            response = receive_response(tls_sock)

    return response, certificate, tls_version, cipher


def _fingerprint_https_with_context(
    target,
    port,
    timeout,
    context,
    verified,
    connect_address=None,
):
    response, certificate, tls_version, cipher = _request_https_with_context(
        target,
        port,
        timeout,
        context,
        "HEAD",
        connect_address,
    )
    info = parse_http_response(response)

    if info["status_code"] in (405, 501) or not response:
        response, certificate, tls_version, cipher = (
            _request_https_with_context(
                target,
                port,
                timeout,
                context,
                "GET",
                connect_address,
            )
        )
        info = parse_http_response(response)

    info.update(
        {
            "tls_cert_cn": extract_common_name(certificate),
            "tls_cert_expiry": normalize_certificate_expiry(
                extract_certificate_expiry(certificate)
            ),
            "tls_version": tls_version,
            "tls_cipher": cipher[0] if cipher else None,
            "certificate_verified": verified,
        }
    )
    return info


def fingerprint_https(target, port, timeout, connect_address=None):
    try:
        return _fingerprint_https_with_context(
            target,
            port,
            timeout,
            ssl.create_default_context(),
            verified=True,
            connect_address=connect_address,
        )
    except ssl.SSLCertVerificationError:
        return _fingerprint_https_with_context(
            target,
            port,
            timeout,
            create_unverified_context(),
            verified=False,
            connect_address=connect_address,
        )


def grab_generic_banner(target, port, timeout, connect_address=None):
    address = connect_address or target
    with socket.create_connection((address, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        try:
            data = sock.recv(1024)
        except socket.timeout:
            return None

    if not data:
        return None

    return data.decode("utf-8", errors="replace").strip()


def guess_service_from_banner(banner):
    if not banner:
        return "TCP"

    lowered = banner.lower()

    if lowered.startswith("ssh-"):
        return "SSH"
    if "smtp" in lowered:
        return "SMTP"
    if "ftp" in lowered:
        return "FTP"
    if "redis" in lowered:
        return "Redis"

    return "TCP"


def _try_https(target, port, timeout, result, connect_address=None):
    try:
        info = fingerprint_https(
            target,
            port,
            timeout,
            connect_address,
        )
    except (ssl.SSLError, socket.timeout, OSError):
        return False

    result["service_guess"] = (
        "HTTPS" if info["status_code"] is not None else "TLS"
    )
    result["banner"] = info
    return True


def _try_http(target, port, timeout, result, connect_address=None):
    try:
        response = fingerprint_http(
            target,
            port,
            timeout,
            connect_address,
        )
        info = parse_http_response(response)
    except (socket.timeout, OSError):
        return False

    if info["status_code"] is None:
        return False

    result["service_guess"] = "HTTP"
    result["banner"] = info
    return True


def _try_generic_banner(target, port, timeout, result, connect_address=None):
    try:
        banner = grab_generic_banner(
            target,
            port,
            timeout,
            connect_address,
        )
    except (socket.timeout, OSError):
        banner = None

    result["service_guess"] = guess_service_from_banner(banner)
    if banner:
        result["banner"] = {"raw_banner": banner[:1000]}
        return True

    return False


def scan_port(target, port, timeout, connect_address=None):
    address = connect_address or target
    status = check_port(address, port, timeout)
    result = {
        "port": port,
        "status": status,
        "service_guess": None,
        "banner": None,
    }

    if status != "open":
        return result

    if port in TLS_PORTS:
        probes = (_try_https, _try_http, _try_generic_banner)
    elif port in HTTP_PORTS:
        probes = (_try_http, _try_https, _try_generic_banner)
    else:
        probes = (_try_generic_banner, _try_https, _try_http)

    for probe in probes:
        if probe(target, port, timeout, result, address):
            return result

    result["service_guess"] = "TCP"
    return result


def scan_ports(target, ports, timeout, workers, connect_address=None):
    results = []
    worker_count = min(workers, len(ports), MAX_WORKERS)

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=worker_count
    ) as executor:
        future_map = {
            executor.submit(
                scan_port,
                target,
                port,
                timeout,
                connect_address,
            ): port
            for port in ports
        }

        for future in concurrent.futures.as_completed(future_map):
            port = future_map[future]
            try:
                result = future.result()
            except Exception as error:
                result = {
                    "port": port,
                    "status": "error",
                    "service_guess": None,
                    "banner": None,
                    "error": str(error),
                }

            results.append(result)

    return sorted(results, key=lambda item: item["port"])


def print_results(target, scan_start, duration, results):
    print()
    print(f"Target       : {sanitize_terminal(target, limit=255)}")
    print(f"Scan started : {scan_start}")
    print()
    print(f"{'PORT':<8}{'STATUS':<12}{'SERVICE':<14}INFO")
    print("-" * 80)

    for result in results:
        port = result["port"]
        status = result["status"].upper()
        service = result["service_guess"] or "-"
        banner = result["banner"]
        info_parts = []

        if banner:
            if banner.get("server_header"):
                info_parts.append(
                    "Server: "
                    f"{sanitize_terminal(banner['server_header'])}"
                )
            if banner.get("status_code") is not None:
                info_parts.append(f"Status: {banner['status_code']}")
            if banner.get("tls_cert_cn"):
                info_parts.append(
                    "Cert CN: "
                    f"{sanitize_terminal(banner['tls_cert_cn'])}"
                )
            if banner.get("tls_cert_expiry"):
                info_parts.append(
                    "Cert expiry: "
                    f"{sanitize_terminal(banner['tls_cert_expiry'])}"
                )
            if banner.get("certificate_verified") is False:
                info_parts.append("Cert: unverified")
            if not info_parts and banner.get("raw_banner"):
                info_parts.append(
                    sanitize_terminal(banner["raw_banner"], limit=70)
                )

        info = " | ".join(info_parts) if info_parts else "-"
        print(f"{port:<8}{status:<12}{service:<14}{info}")

    print()
    print(f"Scan finished in {duration:.2f}s")


def save_json(filename, data):
    with open(filename, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=2, ensure_ascii=False)
        file.write("\n")


def main():
    parser = build_parser()
    args = parser.parse_args()

    try:
        ports = parse_ports(args.ports)
    except ValueError as error:
        parser.error(str(error))

    if args.timeout <= 0:
        parser.error("--timeout harus lebih besar dari 0")
    if args.workers <= 0:
        parser.error("--workers harus lebih besar dari 0")

    try:
        resolved_ip = resolve_target(args.target)
    except socket.gaierror:
        parser.error("Hostname atau IP tidak dapat di-resolve")

    scan_started_at = datetime.now(timezone.utc)
    timer_start = time.perf_counter()
    results = scan_ports(
        target=args.target,
        ports=ports,
        timeout=args.timeout,
        workers=args.workers,
        connect_address=resolved_ip,
    )
    duration = time.perf_counter() - timer_start
    scan_start_text = scan_started_at.isoformat()

    print_results(
        target=args.target,
        scan_start=scan_start_text,
        duration=duration,
        results=results,
    )

    scan_data = {
        "target": args.target,
        "resolved_ip": resolved_ip,
        "scan_start": scan_start_text,
        "scan_duration_seconds": round(duration, 3),
        "ports": results,
    }

    if args.output:
        try:
            save_json(args.output, scan_data)
        except OSError as error:
            parser.error(f"JSON tidak dapat disimpan: {error}")
        print(f"JSON disimpan ke: {args.output}")


if __name__ == "__main__":
    main()
