import socket
import struct

def sniff_packets():
    conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    hostname = socket.gethostname()
    ip = socket.gethostbyname(hostname)

    conn.bind((ip, 0))
    conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    print("Packet sniffing started... Press Ctrl+C to stop.\n")

    try:
        while True:
            data, addr = conn.recvfrom(65535)
            ip_header = data[0:20]
            iph = struct.unpack('!BBHHHBBH4s4s', ip_header)

            src_ip = socket.inet_ntoa(iph[8])
            dst_ip = socket.inet_ntoa(iph[9])
            protocol = iph[6]

            print(f"[+] Source: {src_ip} --> Destination: {dst_ip} | Protocol: {protocol}")

    except KeyboardInterrupt:
        print("\nSniffing stopped.")
        conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)

sniff_packets()
