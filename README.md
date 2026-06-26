# knetutils

A collection of lightweight, high-performance standard network utilities written in C. 

Designed with zero external library dependencies (relying only on standard libc and kernel headers), 
`knetutils` provides standard tools for network diagnostics, packet manipulation, and traffic analysis.

The suite is compiled into a single **Multicall binary**, allowing all utilities to share common core network and 
CLI parsing routines while maintaining a tiny footprint.

## Utilities Included

| Utility | Description | Key Features |
| :--- | :--- | :--- |
| *`arping`* | Discover and probe hosts on a local network using ARP. | Duplicate Address Detection (DAD), unsolicited ARP updates, unit scaling |
| *`ping`* | Diagnose network reachability and RTT latency using ICMP. | Adaptive ping, flood ping, custom payload patterns, TTL/TOS tuning |
| *`pscan`* | Fast asynchronous port scanner. | Non-blocking TCP SYN / UDP scans, rate-limiting, OS fingerprinting, JSON output |
| *`sniff`* | Low-overhead network packet capture utility. | Multiple verbosity levels (headers/payload hex-dump), PCAP file output |
| *`tcping`* | Measure network latency using TCP connection establishment. | Latency to specific TCP ports, custom timeout and interval settings |
| *`traceroute`* | Trace the route and hop latency to a network host. | ICMP Echo or UDP probes, domain name resolution, custom max/first TTL |

## Build & Installation

### Prerequisites

Ensure you have a C compiler (`gcc` or `clang`) and `make` installed on your system.

### 1. Build the Suite Locally

Compile the suite in the project root:

```bash
make
```

This compiles the main binary into `bin/knetutils` and automatically generates symbolic links in `bin/` for each individual tool (`arping`, `ping`, etc.):

```bash
ls -la bin/
```

### 2. Run Tests

Verify build correctness against local loopbacks or network interfaces:

```bash
make test
```

### 3. Install System-Wide

Install the binary, the symbolic links, and the system man pages:

```bash
make install
```

By default, this installs to `/usr/local/bin` and `/usr/local/share/man/man8/`. You can customize the install prefix using:

```bash
make PREFIX=<your-prefix> install
```

### 4. Uninstall

To clean system-wide installation files:

```bash
make uninstall
```

## Command Usage & Examples

You can run any utility in two ways:
1. **Directly** through the symlink: `./bin/ping 1.1.1.1`
2. **Via the dispatcher**: `./bin/knetutils ping 1.1.1.1`

> [!IMPORTANT]
> Because utilities like `ping`, `arping`, `pscan` (SYN scan), `sniff`, and `traceroute` craft or capture raw packets, they require root privileges.

### `arping`
Discover hosts on a local network interface using ARP requests.
```bash
# Discover a host on interface eth0
sudo arping -I eth0 192.168.1.1

# Run Duplicate Address Detection (DAD)
sudo arping -I eth0 -d 192.168.1.50
```

### `ping`
Send ICMP Echo requests to verify connectivity.
```bash
# Send 4 packets with an interval of 500ms
sudo ping -c 4 -i 500 8.8.8.8

# Adaptive ping (adapts interval automatically to RTT)
sudo ping -A google.com
```

### `pscan`
Asynchronously scan network ports for open TCP/UDP services.
```bash
# Perform a fast TCP SYN scan on ports 80 and 443
sudo pscan -p 80,443 1.1.1.1

# Perform a UDP scan with rate limiting (100 packets/sec)
sudo pscan -u -r 100 -p 53,123 8.8.8.8

# Scan ports 1 to 1000 and output results in JSON format
sudo pscan -p 1-1000 -j 192.168.1.1
```

### `sniff`
Sniff and analyze live network packets on an interface.
```bash
# Capture packets on interface eth0 with payload hex-dump
sudo sniff -I eth0 -vv

# Capture 100 packets and write them to a PCAP file for Wireshark analysis
sudo sniff -I eth0 -c 100 -w capture.pcap
```

### `tcping`
Measure latency to a specific TCP port (great for firewall verification).
```bash
# Measure TCP latency to HTTP port 80 (does not require root)
tcping google.com 80
```

### `traceroute`
Print the hop-by-hop route of packets to a host.
```bash
# Classic traceroute to destination
sudo traceroute 8.8.8.8

# Fast UDP traceroute without resolving IP addresses to domain names
sudo traceroute -U -n 1.1.1.1
```

## Development

The project includes standard rules to help contributors format, lint, and analyze the code:

- **Format Code**: Apply uniform code style using `clang-format`.
  ```bash
  make format
  ```
- **Lint Code**: Detect programming errors and code smell using `clang-tidy`.
  ```bash
  make lint
  ```
- **Static Analysis**: Compile with Clang Static Analyzer.
  ```bash
  make analyze
  ```

## License

This project is licensed under the 3-Clause BSD License - see the [LICENSE](LICENSE) file for details.
