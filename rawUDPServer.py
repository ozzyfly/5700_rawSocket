import socket
import sys
from struct import unpack

# Configuration for server
SERVER_IP = '127.0.0.1'  # The IP address the server listens on
SERVER_PORT = 8080       # The port the server listens on (should match client)

try:
    # Create a raw socket to listen for packets
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP) as server_socket:
        # Bind socket to listen to the specified port on SERVER_IP
        server_socket.bind((SERVER_IP, SERVER_PORT))
        print("Server listening for UDP packets on port:", SERVER_PORT)

        while True:
            data, addr = server_socket.recvfrom(65535)
            print(f"Received message from {addr}")

            # Parse the received bytes
            ip_header = data[0:20]
            iph = unpack('!BBHHHBBH4s4s', ip_header)

            ihl = iph[0] & 0x0F
            ip_header_length = ihl * 4

            # UDP header starts after the IP header
            udp_header_start = ip_header_length
            udp_header = data[udp_header_start:udp_header_start+8]
            udp_unpack = unpack('!HHHH', udp_header)

            source_port, dest_port, length, checksum = udp_unpack

            # Extract the payload
            payload_start = udp_header_start + 8
            payload = data[payload_start:payload_start+length-8]
            string_payload = payload.decode('utf-8', errors='ignore')

            print(f"Payload:\n{string_payload}")

            # If we receive data, we assume it's successful (you can implement further checks)
            print("File transfer successful.")

except KeyboardInterrupt:
    print('Server shutting down.')
except socket.error as msg:
    print(f'Error: {msg}')
    sys.exit()
