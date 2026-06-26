# knetutils

The collection of standard network utilities written in C. It provides basic tools for network diagnostics and packet manipulation, working consistently across Linux and macOS/BSD without relying on external dependencies.

## Tools

* **`arping`** - send ARP requests to discover hosts on a local network.
* **`ping`** - send ICMP ECHO_REQUEST packets.
* **`pscan`** - fast asynchronous TCP SYN and UDP port scanner.
* **`sniff`** - capture and display packets from a network interface.
* **`tcping`** - measure latency to a specific TCP port.
* **`traceroute`** - print the route packets trace to a network host.

## Building

To build the suite, just run:
```sh
make
```
This produces a single `knetutils` binary in the `bin/` directory.

## Usage

You can use the combined `knetutils` binary (similar to BusyBox) to run any tool:

```sh
sudo ./bin/knetutils ping 1.1.1.1
sudo ./bin/knetutils pscan -p 80-443 example.com
sudo ./bin/knetutils tcping 1.1.1.1 443
```

> Note: Raw socket operations usually require root privileges
