# Python Traffic Capture Tool

## Overview

This tool captures live network traffic using Python and Scapy. It monitors a selected network interface, extracts important packet information, and exports the captured traffic into CSV or JSON format for further processing.

## Features

* Capture live network traffic from a selected interface
* Extract packet timestamp
* Extract source and destination IP addresses
* Extract source and destination ports
* Detect TCP and UDP protocols
* Record packet length
* Capture TCP flags when applicable
* Export captured traffic to CSV
* Export captured traffic to JSON
* Run continuously until manually stopped
* Handle packet processing errors without crashing

## Requirements

* Python 3.10 or later
* Scapy
* Npcap installed on Windows

## Installation

Create a virtual environment:

```bash
python -m venv venv
```

Activate the virtual environment on Windows:

```bash
.\venv\Scripts\Activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

## Usage

Capture traffic from the Wi-Fi interface and save it as CSV:

```bash
python traffic_capture.py -i "Wi-Fi" -f csv
```

Capture traffic and save it as JSON:

```bash
python traffic_capture.py -i "Wi-Fi" -f json
```

Use a custom output file name:

```bash
python traffic_capture.py -i "Wi-Fi" -o network_data.csv -f csv
```

```bash
python traffic_capture.py -i "Wi-Fi" -o network_data.json -f json
```

Stop the capture by pressing:

```bash
Ctrl + C
```

## Output Fields

The tool exports the following packet information:

* Timestamp
* Source IP
* Destination IP
* Source Port
* Destination Port
* Protocol
* Packet Length
* TCP Flags

## Example CSV Output

```csv
timestamp,source_ip,destination_ip,source_port,destination_port,protocol,packet_length,tcp_flags
2026-07-06T15:19:37.631992,192.168.10.21,170.72.238.46,50066,443,TCP,88,PA
```

## Notes

On Windows, Npcap must be installed for live packet capture to work correctly. If packet capture does not start, run VS Code or PowerShell as Administrator.
