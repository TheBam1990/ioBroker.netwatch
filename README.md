# ioBroker.netwatch

[Deutsche Anleitung](READMEde.md) | English

`ioBroker.netwatch` is a passive Linux network monitor for ioBroker. It uses `dumpcap` for packet capture, PCAPNG for raw data, and `tshark` for Wireshark-compatible protocol decoding. Individual packets are deliberately not exposed as ioBroker states.

> Packet captures can contain passwords, cookies, device identifiers, and other sensitive information. Netwatch neither uploads capture data nor provides firewall, MITM, decryption, or traffic-manipulation features.

## Features

- Detects interfaces and displays IPv4/IPv6, MAC, link status, and RX/TX bytes
- Starts, pauses, resumes, and stops packet captures
- Separates BPF capture filters from validated Wireshark display filters
- Streams live packet batches through WebSocket
- Uses a bounded in-memory ring buffer and configurable storage limits
- Keeps the live fast path small and loads full protocol details on demand
- Displays generic tshark protocol trees plus packet hex/ASCII data
- Records, imports, analyzes, downloads, and safely deletes PCAP/PCAPNG files
- Aggregates conversations, endpoints, devices, and protocol statistics
- Publishes only summarized values as ioBroker states
- Provides a responsive light/dark web interface and guided system checks
- Cleans up capture processes, sockets, streams, and timers on adapter unload

Protocol detection comes from tshark dissectors rather than fixed port assumptions. It includes Ethernet, ARP, IPv4/IPv6, TCP, UDP, ICMP, DNS, DHCP, HTTP, TLS, MQTT, CoAP, NTP, SSDP, Modbus, BACnet, SNMP, SMB, RTP, RTSP, IEC 60870-5-103, IEC 61850, and other protocols decoded by the installed Wireshark version.

## Network visibility

A host connected to a modern switched Ethernet network normally sees its own traffic plus broadcasts and multicasts, but not all traffic from other hosts. Whole-network monitoring usually requires a managed switch SPAN/mirror port, capture on the router or gateway, or a network TAP.

## Requirements

- Linux: Debian, Ubuntu, Raspberry Pi OS, or a comparable distribution
- Node.js 22 or newer
- ioBroker js-controller 6 or newer
- `tshark` and `dumpcap`

Install the Wireshark command-line tools on Debian-derived systems:

```bash
sudo apt update
sudo apt install tshark
```

The **Settings → System setup** page checks whether `tshark` and `dumpcap` are available and whether the unprivileged ioBroker user can list interfaces. A missing dependency does not crash the adapter; the UI and ioBroker states show the problem and provide copyable setup instructions.

## Safe dumpcap permissions

Do not run the adapter as root. Debian packages can permit unprivileged capture through the `wireshark` group and narrowly scoped Linux capabilities:

```bash
sudo dpkg-reconfigure wireshark-common
sudo usermod -aG wireshark iobroker
sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/dumpcap
getcap /usr/bin/dumpcap
sudo systemctl restart iobroker
```

Review these commands for the target system. Netwatch only displays them and never changes privileges automatically. The adapter process remains unprivileged; only `dumpcap` receives packet-capture capabilities.

## Installation

In ioBroker Admin, choose installation from a custom URL and enter:

```text
https://github.com/TheBam1990/ioBroker.netwatch
```

Create an instance and open its web UI. Complete **Settings → System setup**, select an interface, and start a capture. The separate web server binds only to `127.0.0.1` by default. LAN exposure must be selected explicitly and requires a strong username and password.

For local development packages:

```bash
npm ci
npm run check
npm pack
```

Install the resulting archive through ioBroker Admin or on the host:

```bash
sudo -u iobroker iobroker url /path/iobroker.netwatch-0.1.1.tgz
sudo -u iobroker iobroker add netwatch
```

## Configuration

- **Capture interface:** interface such as `eth0` or `enp3s0`
- **Auto start:** begin capturing when the adapter starts
- **Memory packet limit:** 10,000, 50,000, or 100,000 live rows
- **Capture directory:** empty selects the ioBroker adapter data directory
- **Maximum capture size / total storage / retention:** storage boundaries
- **Web bind:** `127.0.0.1` by default; `0.0.0.0` explicitly exposes it to LAN
- **Web port:** `8110` by default
- **Web username/password:** required when binding outside localhost

HTTP Basic Authentication protects the standalone interface. Use a TLS reverse proxy when accessing sensitive capture data across an untrusted network.

## Filters

Capture filters are BPF expressions. They reduce data before it is stored:

```text
host 192.168.1.50 and tcp
port 1883
```

Display filters use Wireshark syntax and filter decoded output:

```text
ip.addr == 192.168.1.55
tcp.port == 443 && tls
mqtt.topic contains "zigbee2mqtt"
```

Netwatch validates display filters with tshark before applying them. An invalid display filter reports the tshark error without stopping the active capture.

## Capture files

Each session receives a random identifier and a dedicated `.pcapng` file. The Captures page supports download, analysis, import, and confirmed deletion. Imports accept only `.pcap` and `.pcapng`, enforce upload limits, reject unsafe paths, and remain inside the configured adapter data directory.

## Troubleshooting

- **tshark or dumpcap missing:** install the `tshark` package.
- **Permission denied:** check group membership and `getcap /usr/bin/dumpcap`, then restart the complete ioBroker service.
- **Traffic from other devices missing:** configure a mirror port, router capture, or TAP.
- **Filter rejected:** distinguish BPF capture filters from Wireshark display filters.
- **Web UI unavailable:** verify bind address, port, firewall, and adapter log.
- **Interface disappeared:** stop capture, select an available interface, and start again.

## Development and tests

```bash
npm run build
npm test
npm run lint
```

Tests cover input and path validation, parser normalization, the bounded ring buffer, and conversation/device aggregation. Test data is synthetic; private network captures must never be committed.

## Current scope

Version 0.1.1 exposes decoded DNS, MQTT, TLS, and HTTP traffic through the live packet table and generic detail path. Dedicated historical field tables and SQLite metadata persistence are planned for a later release. PCAPNG raw data, generic full decoding, bounded live analysis, and aggregated statistics are already available.

## Changelog

### 0.1.1 (2026-09-11)

- Added guided dependency and capture-permission checks
- Added a dedicated adapter icon
- Improved GitHub installation documentation and repository metadata

### 0.1.0

- Initial packet capture, analysis, web UI, and PCAPNG release

## License

MIT License

Copyright (c) 2026 TheBam1990
