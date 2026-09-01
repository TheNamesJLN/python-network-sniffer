import argparse
import datetime
import socket
import struct
import sys
from pathlib import Path


def parse_ip_packet(packet: bytes):
    if len(packet) < 34:
        return None

    ethernet_header = packet[:14]
    eth_type = struct.unpack('!H', ethernet_header[12:14])[0]
    if eth_type != 0x0800:
        return None

    ip_header = packet[14:34]
    version_ihl = ip_header[0]
    ihl = (version_ihl & 0x0F) * 4
    if len(packet) < 14 + ihl:
        return None

    protocol = ip_header[9]
    src_ip = socket.inet_ntoa(ip_header[12:16])
    dst_ip = socket.inet_ntoa(ip_header[16:20])

    return src_ip, dst_ip, protocol


def get_local_ip(destination_ip: str) -> str:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.connect((destination_ip, 80))
        return sock.getsockname()[0]


def protocol_name(protocol_number: int) -> str:
    if protocol_number == 1:
        return 'ICMP'
    if protocol_number == 6:
        return 'TCP'
    if protocol_number == 17:
        return 'UDP'
    return f'PROTO-{protocol_number}'


def write_session_logs(logs, output_file: Path):
    with output_file.open('w', encoding='utf-8') as file:
        if logs:
            file.write('\n'.join(logs) + '\n')
    print(f'\nSession logs saved to {output_file}')


def sniff_traffic(destination_ip: str, output_file: Path):
    local_ip = get_local_ip(destination_ip)
    logs = []

    print(f'Local IP: {local_ip}')
    print(f'Destination IP: {destination_ip}')
    print('Sniffing traffic... Press Ctrl+C to stop.\n')

    try:
        with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003)) as sniffer:
            while True:
                packet, _ = sniffer.recvfrom(65535)
                parsed_packet = parse_ip_packet(packet)
                if not parsed_packet:
                    continue

                src_ip, dst_ip, protocol = parsed_packet
                is_outgoing = src_ip == local_ip and dst_ip == destination_ip
                is_incoming = src_ip == destination_ip and dst_ip == local_ip

                if not (is_outgoing or is_incoming):
                    continue

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
    parser = argparse.ArgumentParser(
        description='Basic packet sniffer for traffic between this device and a destination IP.'
    )
    parser.add_argument('destination_ip', help='Destination IPv4 address to monitor')
    args = parser.parse_args()

    try:
        socket.inet_aton(args.destination_ip)
    except OSError:
        print('Invalid destination IP address.')
        sys.exit(1)

    sniff_traffic(args.destination_ip, Path('sessionlogs.txt'))


if __name__ == '__main__':
    main()
