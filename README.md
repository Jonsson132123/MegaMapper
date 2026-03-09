# MegaMapper

A command-line network scanner built in Python, inspired by Nmap. I built this to get better at programming, learn how networking works under the hood, and understand how security tools like Nmap actually do what they do.

> **!!Educational use only. Run against your own lab network or authorized systems.**

---

## Features

- **Port scanning** — TCP connect scan with concurrent threading (fast)
- **Host discovery** — ARP sweep to find live hosts on a subnet
- **Service detection** — Identifies known services by port number
- **Banner grabbing** — Connects to open ports and reads service banners (SSH version, HTTP server, etc.)
- **Flexible CLI** — Supports single targets, subnets, and port ranges via `argparse`

---

## Usage

```bash
# Scan a single host, ports 1-1024
python MegaMapper.py -t 192.168.1.1 -p 1-1024

# Scan a single port
python MegaMapper.py -t 192.168.1.1 -p 80

# Host discovery on a subnet (no port scan)
python MegaMapper.py -s 192.168.1.0/24 --no-port

# Full scan: host discovery + port scan on every live host
python MegaMapper.py -s 192.168.1.0/24 -p 1-1024
```

**Note:** Host discovery (ARP) requires the terminal to be run as Administrator/root, since raw packet crafting needs elevated privileges.

---

## Example Output

```
MegaMapper v1.1 - Networkscanner
Albin Jonsson 2026-02-26
================================

[*] Executing port scan on 192.168.1.1...

[+] 22   open   ssh      SSH-2.0-OpenSSH_8.9p1
[+] 80   open   http
[+] 443  open   https

[*] Scan completed in 2.3 seconds
```

---

## Dependencies

```bash
pip install scapy
```

| Library | Purpose |
|---------|---------|
| `socket` | TCP connect scan, service lookup |
| `scapy` | ARP packets for host discovery |
| `concurrent.futures` | Thread pool for parallel port scanning |
| `argparse` | CLI argument parsing |
| `threading` | Spinner animation while scanning |

---

## Concepts Learned

**TCP Connect Scan**
The scanner opens a full TCP connection (`socket.connect_ex()`) to each port. If the connection succeeds (return code 0), the port is open. This is the most reliable scan method — no raw packets, works without admin rights for port scanning.

**ARP Host Discovery**
Scapy crafts an ARP request broadcast to the entire subnet (`ff:ff:ff:ff:ff:ff`). Hosts that respond are alive. This works at Layer 2 and is faster and more reliable than ICMP ping on local networks.

**Threading with ThreadPoolExecutor**
Scanning ports sequentially would be extremely slow (100ms timeout × 1024 ports = ~100 seconds). By using a thread pool with 100 workers, all ports are scanned concurrently, reducing total time to a few seconds.

**Banner Grabbing**
After finding an open port, the scanner connects and sends a blank line (`\r\n`). Many services (SSH, FTP, SMTP) respond with a banner identifying the software and version — useful for fingerprinting.

**Argument Parsing**
`argparse` provides a structured way to handle CLI flags (`-t`, `-s`, `-p`, `--no-port`), automatically generates a help menu, and validates input types.

---

## What I Would Improve

- Better error handling for invalid inputs (e.g. malformed IP, out-of-range ports)
- UDP scan support
- Output to file (`-o output.txt`)
- OS detection based on TTL values
