"""
Network packet sniffer for monitoring traffic between this device and a destination IP.
Captures and logs packet details including source IP, destination IP, and protocol type.
"""
import argparse
import datetime
import socket
import struct
import sys
from pathlib import Path


def parse_ip_packet(packet: bytes):
    """
    Extract IP packet information from raw packet data.
    
    Args:
        packet: Raw packet bytes from network interface
        
    Returns:
        Tuple of (source_ip, destination_ip, protocol_number) or None if packet is invalid
    """
    # Check minimum packet size (Ethernet + IP headers)
    if len(packet) < 34:
        return None

    # Parse Ethernet frame header (first 14 bytes)
    ethernet_header = packet[:14]
    eth_type = struct.unpack('!H', ethernet_header[12:14])[0]
    
    # Only process IPv4 packets (EtherType 0x0800)
    if eth_type != 0x0800:
        return None

    # Extract IP header (20 bytes minimum)
    ip_header = packet[14:34]
    version_ihl = ip_header[0]
    # Calculate actual IP header length (last 4 bits × 4 bytes)
    ihl = (version_ihl & 0x0F) * 4
    if len(packet) < 14 + ihl:
        return None

    # Extract protocol number from IP header (ICMP=1, TCP=6, UDP=17)
    protocol = ip_header[9]
    # Extract source and destination IP addresses (4 bytes each)
    src_ip = socket.inet_ntoa(ip_header[12:16])
    dst_ip = socket.inet_ntoa(ip_header[16:20])

    return src_ip, dst_ip, protocol


def get_local_ip(destination_ip: str) -> str:
    """
    Determine the local IP address used to reach the destination.
    
    Creates a temporary socket connection to find which local interface
    would be used for outgoing traffic to the destination.
    
    Args:
        destination_ip: Target IP address
        
    Returns:
        Local IP address as string
    """
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.connect((destination_ip, 80))
        return sock.getsockname()[0]


def protocol_name(protocol_number: int) -> str:
    """
    Convert protocol number to human-readable protocol name.
    
    Args:
        protocol_number: IP protocol number
        
    Returns:
        Protocol name (e.g., 'TCP', 'UDP', 'ICMP') or 'PROTO-X' for unknown protocols
    """
    if protocol_number == 1:
        return 'ICMP'
    if protocol_number == 6:
        return 'TCP'
    if protocol_number == 17:
        return 'UDP'
    return f'PROTO-{protocol_number}'


def write_session_logs(logs, output_file: Path):
    """
    Write captured packet logs to a file and print confirmation message.
    
    Args:
        logs: List of log line strings to write
        output_file: Path object for the output file
    """
    with output_file.open('w', encoding='utf-8') as file:
        if logs:
            file.write('\n'.join(logs) + '\n')
    print(f'\nSession logs saved to {output_file}')


def sniff_traffic(destination_ip: str, output_file: Path):
    """
    Capture and log network packets between local host and destination IP.
    
    Opens a raw socket to listen on the network interface, filters packets
    for those between the local machine and destination IP, and logs them.
    Catches KeyboardInterrupt (Ctrl+C) to gracefully stop sniffing.
    
    Args:
        destination_ip: Target IP address to monitor traffic for
        output_file: Path where session logs should be saved
    """
    local_ip = get_local_ip(destination_ip)
    logs = []

    print(f'Local IP: {local_ip}')
    print(f'Destination IP: {destination_ip}')
    print('Sniffing traffic... Press Ctrl+C to stop.\n')

    try:
        # Create raw socket to capture all packets on the network interface
        # AF_PACKET: packet-level interface on Linux
        # SOCK_RAW: receive raw packets
        # ntohs(0x0003): ETH_P_ALL - capture all protocols
        with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003)) as sniffer:
            while True:
                # Receive raw packet data (up to 65535 bytes)
                packet, _ = sniffer.recvfrom(65535)
                parsed_packet = parse_ip_packet(packet)
                if not parsed_packet:
                    continue

                src_ip, dst_ip, protocol = parsed_packet
                # Check if packet is outgoing (local -> destination)
                is_outgoing = src_ip == local_ip and dst_ip == destination_ip
                # Check if packet is incoming (destination -> local)
                is_incoming = src_ip == destination_ip and dst_ip == local_ip

                # Only log packets relevant to the destination
                if not (is_outgoing or is_incoming):
                    continue

                # Format log entry with timestamp and direction
                direction = 'OUT' if is_outgoing else 'IN '
                timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                log_line = (
                    f'[{timestamp}] {direction} {protocol_name(protocol)} '
                    f'{src_ip} -> {dst_ip}'
                )
                logs.append(log_line)
                print(log_line)

    except KeyboardInterrupt:
        print('\nStopping packet sniffer...')
    except PermissionError:
        print('Permission denied: run this script with elevated privileges (e.g. sudo).')
    finally:
        write_session_logs(logs, output_file)


def main():
    """
    Entry point for the packet sniffer application.
    
    Parses command-line arguments (destination IP), validates the IP address,
    and starts the traffic sniffing session.
    """
    # Create argument parser for command-line interface
    parser = argparse.ArgumentParser(
        description='Basic packet sniffer for traffic between this device and a destination IP.'
    )
    parser.add_argument('destination_ip', help='Destination IPv4 address to monitor')
    args = parser.parse_args()

    # Validate that the provided destination is a valid IPv4 address
    try:
        socket.inet_aton(args.destination_ip)
    except OSError:
        print('Invalid destination IP address.')
        sys.exit(1)

    # Start sniffing traffic to/from the destination IP
    sniff_traffic(args.destination_ip, Path('sessionlogs.txt'))

# Run the sniffer when script is executed directly
if __name__ == '__main__':
    main()
