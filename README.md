# python-network-sniffer

A basic Python packet sniffer that logs traffic between your device and a destination IP.

## Usage

```bash
sudo python3 sniffer.py <destination_ip>
```

- Captured matching traffic is printed to the console in real time.
- When you stop the process (Ctrl+C), the session logs are written to `sessionlogs.txt`.
