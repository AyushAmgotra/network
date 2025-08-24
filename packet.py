import socket
import struct

# Function to format MAC addresses
def mac_addr(mac_bytes):
    return ':'.join('%02x' % b for b in mac_bytes)

# Function to format IP addresses
def ip_addr(addr_bytes):
    return '.'.join(map(str, addr_bytes))

# Create raw socket (Ethernet + IP packets)
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

print("Starting Packet Sniffer... Press CTRL+C to stop.\n")

while True:
    raw_data, addr = s.recvfrom(65535)

    # Unpack Ethernet header
    eth_header = struct.unpack("!6s6sH", raw_data[0:14])
    dest_mac = mac_addr(eth_header[0])
    src_mac = mac_addr(eth_header[1])
    proto = socket.htons(eth_header[2])

    print("\nEthernet Frame:")
    print(f"   Destination: {dest_mac}, Source: {src_mac}, Protocol: {proto}")

    # IPv4 Packet
    if proto == 8:
        # Unpack IP header
        ip_header = struct.unpack("!BBHHHBBH4s4s", raw_data[14:34])
        version_ihl = ip_header[0]
        version = version_ihl >> 4
        ihl = (version_ihl & 15) * 4
        ttl = ip_header[5]
        proto_ip = ip_header[6]
        src_ip = ip_addr(ip_header[8])
        dest_ip = ip_addr(ip_header[9])

        print("IPv4 Packet:")
        print(f"   Version: {version}, Header Length: {ihl}, TTL: {ttl}")
        print(f"   Protocol: {proto_ip}, Source: {src_ip}, Destination: {dest_ip}")

        # TCP
        if proto_ip == 6:
            tcp_header = struct.unpack("!HHLLBBHHH", raw_data[14+ihl:14+ihl+20])
            src_port, dest_port = tcp_header[0], tcp_header[1]
            print("   TCP Segment:")
            print(f"      Source Port: {src_port}, Destination Port: {dest_port}")

        # UDP
        elif proto_ip == 17:
            udp_header = struct.unpack("!HHHH", raw_data[14+ihl:14+ihl+8])
            src_port, dest_port = udp_header[0], udp_header[1]
            print("   UDP Segment:")
            print(f"      Source Port: {src_port}, Destination Port: {dest_port}")

        # ICMP
        elif proto_ip == 1:
            print("   ICMP Packet")

