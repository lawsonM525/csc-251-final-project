import socket
import argparse
import time
import random
from concurrent.futures import ThreadPoolExecutor
from scapy.all import IP, ICMP, sr1, TCP, UDP, sr
import os

# convert the hostname to an IP address
def resolve_target(target):
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        print("Error: Invalid hostname.")
        return None

# check if the target is alive
def is_alive(ip):
    icmp_packet = IP(dst=ip)/ICMP()
    resp = sr1(icmp_packet, timeout=1, verbose=0)
    return resp is not None

# get the list of ports to scan based on the mode
# known ports are 0-1023, all ports are 0-65535
def get_ports(mode):
    if mode == "known":
        return list(range(0, 1024))
    else:
        return list(range(0, 65536))

# scan the target using different methods
# connect scan
def scan_connect(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((ip, port))
        if result == 0:
            try:
                banner = sock.recv(1024).decode().strip()
            except:
                banner = "No banner"
            return port, "open", banner
        return port, "closed", ""
    finally:
        sock.close()

# SYN scan
def scan_syn(ip, port):
    pkt = IP(dst=ip)/TCP(dport=port, flags="S")
    resp = sr1(pkt, timeout=1, verbose=0)
    if resp and resp.haslayer(TCP) and resp.getlayer(TCP).flags == 0x12:
        return port, "open"
    else:
        return port, "closed"

# UDP scan
def scan_udp(ip, port):
    pkt = IP(dst=ip)/UDP(dport=port)
    resp = sr1(pkt, timeout=1, verbose=0)
    if not resp:
        return port, "open/filtered"
    elif resp.haslayer(ICMP):
        return port, "closed"
    else:
        return port, "unknown"

# worker function to handle threading
def worker(ip, port, mode):
    print(".", end="", flush=True)
    if mode == "connect":
        return scan_connect(ip, port)
    elif mode == "syn":
        p, s = scan_syn(ip, port)
        return p, s, ""
    elif mode == "udp":
        p, s = scan_udp(ip, port)
        return p, s, ""
    return port, "error", ""

# parse arguments and run the scan
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("target", help="Target IP or hostname")
    parser.add_argument("-mode", choices=["connect", "syn", "udp"], default="connect")
    parser.add_argument("-order", choices=["order", "random"], default="order")
    parser.add_argument("-ports", choices=["all", "known"], default="known")
    args = parser.parse_args()

    ip = resolve_target(args.target)
    if not ip:
        return

    print(f"Resolved target to IP: {ip}")
    print("Checking if target is alive...")
    if not is_alive(ip):
        print("Target not reachable.")
        return
    print("Target is alive.\n")

    ports = get_ports(args.ports)
    if args.order == "random":
        random.shuffle(ports)

    print(f"Scanning {len(ports)} ports using {args.mode.upper()} mode...\n")

    start_time = time.time()
    results = []
    # set the maximum number of threads to 500 or 10 times the number of CPU cores
    max_threads = min(500, (os.cpu_count() or 4) * 10)
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = [executor.submit(worker, ip, port, args.mode) for port in ports]
        for future in futures:
            results.append(future.result())
    print("\n\nScan complete.")
    print(f"Time taken: {round(time.time() - start_time, 2)} seconds")
    print("\nOpen Ports:")
    for port, status, banner in results:
        if status == "open" or status == "open/filtered":
            try:
                service = socket.getservbyport(port)
            except:
                service = "Unknown"
            print(f"Port {port}: {status} - {service} - {banner}")

if __name__ == "__main__":
    main()
