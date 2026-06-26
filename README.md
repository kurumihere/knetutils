# knetutils

`knetutils` is a modern, cross-platform set of senior-level C network utilities written from scratch. It relies on standard POSIX networking structures and OS-level abstractions (like AF_PACKET on Linux or BPF on macOS/BSD) to avoid deep logic nesting and heavy dependencies.

## Utilities

* **`arping`** - discover and probe hosts on a local network using ARP.
* **`ping`** - send ICMP ECHO_REQUEST packets to network hosts.
* **`pscan`** - fast asynchronous TCP SYN and UDP port scanner. Measures latency to target ports.
* **`sniff`** - capture and display packets on a network interface.
* **`tcping`** - measure latency to a host using TCP SYN packets.
* **`traceroute`** - print the route packets trace to network host.

## Building

```sh
make
```
All binaries will be compiled and linked together into a single monolithic binary `bin/knetutils`, which dispatches commands similarly to BusyBox.

## Usage

You can use the combined `knetutils` binary:
```sh
sudo ./bin/knetutils ping 1.1.1.1
sudo ./bin/knetutils pscan -p 80-443 example.com
```

Or you can use symlinks or run the tools directly if installed to `$PATH`.

## Features
- **Zero Dependencies**: Pure C11 code using standard system headers.
- **Cross Platform**: Abstracted raw socket implementations working seamlessly across Linux and macOS/BSD.
- **Aesthetic**: Dynamic metric scaling (`ns` -> `μs` -> `ms`) and clean, colorful CLI output.
- **Strict Style**: Zero comments, max 3 levels of nested logic, entirely flat architecture.

## License
MIT
