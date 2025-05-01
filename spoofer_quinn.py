# source: tutorial video, https://scapy.readthedocs.io/en/latest/extending.html, https://stackoverflow.com/questions/20429674/get-tcp-flags-with-scapy
# discussed with Malaz, Michelle 

from scapy.all import *

ip = IP(src="127.0.0.1", dst="10.10.33.165")
# I tried to use the IP src of 192.168.0.1, as the tutorial video used, and dst = 10.10.33.165, but it failed to show up on wireshark.
# also tried using dst of 8.8.8.8, it showed up on wireshark.

tcp = TCP(sport=12345, dport=80, flags="S", seq=1000)

packet = ip / tcp
send(packet)
print("SYN packet sent.")

# sniffing for response
def monitor_response(packet):
    if packet.haslayer(TCP) and packet[TCP].flags == "SA":
        print("Received SYN-ACK: spoofed connection may have succeeded.")
    elif packet.haslayer(TCP) and packet[TCP].flags == "RA":
        print("Received RST-ACK: connection refused or reset.")
    else:
        print("other response received.")
        
print("sniffing for response...")
sniff(prn=monitor_response, timeout=5)
print("Sniffing stopped.")
