# TCP Port Scanner

A beginner Python project that checks selected TCP ports on a host using concurrent connections. It displays open ports, familiar service names, and banners when a service sends one.

## Features

- Scan a port range or comma-separated list
- Scan multiple ports concurrently
- Show open ports and available banners
- Limit scans to 1,024 ports and 32 workers

## Requirements

Python 3. No external Python packages are required.

## Run

Scan selected ports on your own computer:

```powershell
python port_scanner.py 127.0.0.1 --ports 80,443,6541,8000,8501
```

Scan a range:

```powershell
python port_scanner.py 127.0.0.1 --ports 20-100
```

## Understanding the results

An **open** result means a TCP connection succeeded. Service names are based on standard port mappings; they do not prove which application is running. A blank banner means the service did not send identifying text immediately.

In my local test, ports 80 and 443 were open. I verified separately that Apache inside WSL was listening on them.

Only scan systems you own or are authorized to test.