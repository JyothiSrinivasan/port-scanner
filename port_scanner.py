import argparse
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed


def parse_ports(value):
    """Accept a range like 20-100 or a list like 22,80,443."""
    ports = set()

    for part in value.split(","):
        part = part.strip()

        if "-" in part:
            start, end = map(int, part.split("-", 1))
            if start > end:
                raise ValueError("The first port must be smaller than the last.")
            ports.update(range(start, end + 1))
        else:
            ports.add(int(part))

    if not ports or min(ports) < 1 or max(ports) > 65535:
        raise ValueError("Ports must be between 1 and 65535.")

    if len(ports) > 1024:
        raise ValueError("Scan at most 1024 ports at a time.")

    return sorted(ports)


def service_name(port):
    """Return a familiar service name, if Python knows one."""
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def scan_port(ip, port, timeout=1.0):
    """Try to make a TCP connection to one port."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as connection:
            connection.settimeout(0.3)

            # Some services greet a client first; many do not.
            try:
                banner = connection.recv(80).decode(
                    "utf-8", errors="replace"
                ).strip()
            except (socket.timeout, OSError):
                banner = ""

            banner = banner.replace("\r", " ").replace("\n", " ")[:80]
            return port, "open", banner

    except ConnectionRefusedError:
        return port, "closed", ""

    except socket.timeout:
        return port, "no response", ""

    except OSError:
        return port, "unreachable/error", ""


def main():
    parser = argparse.ArgumentParser(
        description="Small TCP connect scanner for hosts you own or may test."
    )
    parser.add_argument("host", help="Hostname or IPv4 address")
    parser.add_argument(
        "--ports",
        default="20-100",
        help="Port range or list; default: 20-100",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=20,
        help="Concurrent connections, 1-32; default: 20",
    )
    args = parser.parse_args()

    try:
        ports = parse_ports(args.ports)
        if not 1 <= args.workers <= 32:
            parser.error("--workers must be between 1 and 32")
        ip = socket.gethostbyname(args.host)
    except (ValueError, socket.gaierror) as error:
        parser.error(str(error))

    print(f"Scanning {args.host} ({ip})")
    print(f"TCP ports: {len(ports)} | Workers: {args.workers}\n")

    results = []

    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {
            executor.submit(scan_port, ip, port): port
            for port in ports
        }

        for future in as_completed(futures):
            results.append(future.result())

    print(f"{'PORT':<10} {'STATE':<20} {'SERVICE':<15} BANNER")
    print("-" * 70)

    for port, state, banner in sorted(results):
        if state == "open":
            print(
                f"{port:<10} {state:<20} "
                f"{service_name(port):<15} {banner or '-'}"
            )

    open_count = sum(state == "open" for _, state, _ in results)
    print(f"\nOpen ports: {open_count} / {len(ports)} scanned")


if __name__ == "__main__":
    main()