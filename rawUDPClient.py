import socket
import sys
from struct import pack

# Configuration for client
CLIENT_IP = '127.0.0.1'  # Localhost (for testing purposes)
# Localhost (should be set to the server's IP in production)
SERVER_IP = '127.0.0.1'
CLIENT_PORT = 1234       # Arbitrary non-privileged port for the client
SERVER_PORT = 8080       # The server port that listens for incoming packets


def checksum(msg):
    """Compute and return a checksum of the given data."""
    s = 0
    for i in range(0, len(msg), 2):
        w = (msg[i] << 8) + (msg[i+1] if i+1 < len(msg) else 0)
        s = s + w

    s = (s >> 16) + (s & 0xffff)
    s = s + (s >> 16)
    s = ~s & 0xffff
    return s


if __name__ == "__main__":
    # Name of the file to send
    file_name = "1.txt"

    try:
        # Read the file content to send
        with open(file_name, "rb") as file:
            file_contents = file.read()

        # Create a raw socket capable of sending UDP packets
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW) as client_socket:
            client_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            print("Raw socket successfully created.")

            # IP Header construction
            ip_ver = 4  # IPv4
            ip_ihl = 5  # Header Length =5x32-bit words
            ip_tos = 0  # Type of Service
            ip_tot_len = 0  # Kernel will fill the correct total length
            ip_id = 54321  # Id of this packet
            ip_frag_off = 0  # Fragment offset
            ip_ttl = 255  # Time to live
            ip_proto = socket.IPPROTO_UDP  # Protocol
            ip_check = 0  # Kernel will fill the correct checksum
            ip_saddr = socket.inet_aton(CLIENT_IP)  # Source IP
            ip_daddr = socket.inet_aton(SERVER_IP)  # Destination IP
            ip_ihl_ver = (ip_ver << 4) + ip_ihl  # Version and header length

            # IP total length = IP header + UDP header + data
            ip_tot_len = 20 + 8 + len(file_contents)

            # The IP header without checksum
            ip_header = pack('!BBHHHBBH4s4s', ip_ihl_ver, ip_tos, ip_tot_len,
                             ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)
            # Calculate the checksum based on this header
            ip_check = checksum(ip_header)
            ip_header = pack('!BBHHHBBH4s4s', ip_ihl_ver, ip_tos, ip_tot_len,
                             ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)

            # For debugging: print the IP header in hexadecimal
            print(f"IP Header: {ip_header.hex()}")

            # UDP Header fields
            udp_src_port = CLIENT_PORT
            udp_dest_port = SERVER_PORT
            udp_len = 8 + len(file_contents)
            udp_check = 0  # Set checksum to zero indicating it's not used

            # Pack the UDP header without calculating checksum
            udp_header = pack('!HHHH', udp_src_port,
                              udp_dest_port, udp_len, udp_check)

            # Pseudo header fields for checksum calculation
            pseudo_header = pack('!4s4sBBH', ip_saddr,
                                 ip_daddr, 0, ip_proto, udp_len)
            udp_check = checksum(pseudo_header + udp_header +
                                 file_contents)  # Correct checksum
            udp_header = pack('!HHHH', udp_src_port,
                              udp_dest_port, udp_len, udp_check)

            # For debugging: print the UDP header in hexadecimal
            print(f"UDP Header: {udp_header.hex()}")

            # Construct the final packet
            packet = ip_header + udp_header + file_contents

            # Send the packet to server
            client_socket.sendto(packet, ("", 0))
            print("Packet sent.")

    except FileNotFoundError:
        print(f"File {file_name} does not exist.")
    except socket.error as msg:
        print(f'Error: {msg}')
        sys.exit()
    except Exception as e:
        print(f'An error occurred: {e}')
        sys.exit()
