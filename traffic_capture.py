from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime
import csv
import json
import os
import argparse


FIELDNAMES = [
    "timestamp",
    "source_ip",
    "destination_ip",
    "source_port",
    "destination_port",
    "protocol",
    "packet_length",
    "tcp_flags"
]


def extract_packet_info(packet):
    """
    Extract useful metadata from a captured packet.
    """
    packet_data = {
        "timestamp": datetime.now().isoformat(),
        "source_ip": None,
        "destination_ip": None,
        "source_port": None,
        "destination_port": None,
        "protocol": "OTHER",
        "packet_length": len(packet),
        "tcp_flags": None
    }

    if packet.haslayer(IP):
        packet_data["source_ip"] = packet[IP].src
        packet_data["destination_ip"] = packet[IP].dst

    if packet.haslayer(TCP):
        packet_data["protocol"] = "TCP"
        packet_data["source_port"] = packet[TCP].sport
        packet_data["destination_port"] = packet[TCP].dport
        packet_data["tcp_flags"] = str(packet[TCP].flags)

    elif packet.haslayer(UDP):
        packet_data["protocol"] = "UDP"
        packet_data["source_port"] = packet[UDP].sport
        packet_data["destination_port"] = packet[UDP].dport

    return packet_data


def save_to_csv(packet_data, output_file):
    """
    Save packet data to a CSV file.
    """
    file_exists = os.path.isfile(output_file)

    with open(output_file, mode="a", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=FIELDNAMES)

        if not file_exists:
            writer.writeheader()

        writer.writerow(packet_data)


def save_to_json(packet_data, output_file):
    """
    Save packet data to a JSON file as a list of packet records.
    """
    packets = []

    if os.path.isfile(output_file) and os.path.getsize(output_file) > 0:
        try:
            with open(output_file, mode="r", encoding="utf-8") as file:
                packets = json.load(file)
        except json.JSONDecodeError:
            packets = []

    packets.append(packet_data)

    with open(output_file, mode="w", encoding="utf-8") as file:
        json.dump(packets, file, indent=4)


def save_packet(packet_data, output_file, output_format):
    """
    Save packet data based on the selected output format.
    """
    if output_format == "csv":
        save_to_csv(packet_data, output_file)
    elif output_format == "json":
        save_to_json(packet_data, output_file)


def process_packet(packet, output_file, output_format):
    """
    Process each captured packet safely without stopping the capture.
    """
    try:
        packet_data = extract_packet_info(packet)
        save_packet(packet_data, output_file, output_format)
        print(packet_data)

    except Exception as error:
        print(f"Error processing packet: {error}")


def start_capture(interface, output_file, output_format):
    """
    Start live packet capture on the selected network interface.
    """
    print("Starting packet capture...")
    print(f"Interface: {interface}")
    print(f"Output file: {output_file}")
    print(f"Output format: {output_format.upper()}")
    print("Press CTRL + C to stop.\n")

    try:
        sniff(
            iface=interface,
            prn=lambda packet: process_packet(packet, output_file, output_format),
            store=False
        )

    except KeyboardInterrupt:
        print("\nPacket capture stopped by user.")

    except Exception as error:
        print(f"Capture failed: {error}")


def main():
    """
    Parse command-line arguments and run the packet capture tool.
    """
    parser = argparse.ArgumentParser(
        description="Python traffic capture tool for Synapse IPS"
    )

    parser.add_argument(
        "-i",
        "--interface",
        required=True,
        help='Network interface to capture packets from, example: "Wi-Fi"'
    )

    parser.add_argument(
        "-o",
        "--output",
        default=None,
        help="Output file name"
    )

    parser.add_argument(
        "-f",
        "--format",
        choices=["csv", "json"],
        default="csv",
        help="Output format: csv or json"
    )

    args = parser.parse_args()

    if args.output is None:
        args.output = f"captured_traffic.{args.format}"

    start_capture(args.interface, args.output, args.format)


if __name__ == "__main__":
    main()