import os
import logging
import struct
import socket



class Config:
    # Configure logging
    log_path = os.path.join(os.path.dirname(__file__), 'server.log')
    logging.basicConfig(filename=log_path, level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    # Constants
    SERVER_IP = "192.168.1.1"
    SUBNET_MASK = "255.255.255.0"
    DNS_SERVER = SERVER_IP
    LEASE_TIME = 86400  # 1 day
    MAGIC_COOKIE = b'\x63\x82\x53\x63'
    
    @classmethod
    def create_dhcp_packet(cls, message_type, xid, yiaddr, chaddr, offered_ip):
        """Create a DHCP packet with all specified options in order."""
        packet = struct.pack(
            '!BBBBIHHIIII16s192x',
            2, 1, 6, 0, xid, 0, 0x8000,
            0, struct.unpack("!I", socket.inet_aton(yiaddr))[0],
            struct.unpack("!I", socket.inet_aton(cls.SERVER_IP))[0], 0,
            chaddr.ljust(16, b'\x00')
        )

        # Add Magic Cookie
        packet += cls.MAGIC_COOKIE

        # DHCP Options in order
        options = [
            (1, 4, socket.inet_aton(cls.SUBNET_MASK)),  # Subnet Mask
            (2, 4, (0).to_bytes(4, 'big')),  # Time Offset
            (3, 4, socket.inet_aton(cls.SERVER_IP)),  # Router (Default Gateway)
            (4, 4, socket.inet_aton("192.168.1.2")),  # Time Server
            (5, 4, socket.inet_aton("192.168.1.3")),  # Name Server
            (6, 4, socket.inet_aton(cls.DNS_SERVER)),  # Domain Name Server
            (7, 4, socket.inet_aton("192.168.1.4")),  # Log Server
            (8, 4, socket.inet_aton("192.168.1.5")),  # Cookie Server
            (9, 4, socket.inet_aton("192.168.1.6")),  # LPR Server
            (10, 4, socket.inet_aton("192.168.1.7")),  # Impress Server
            (11, 4, socket.inet_aton("192.168.1.8")),  # RLP Server
            (12, len("hostname"), b"hostname"),  # Hostname
            (15, len("domain.local"), b"domain.local"),  # Domain Name
            (28, 4, socket.inet_aton("255.255.255.255")),  # Broadcast Address
            (50, 4, socket.inet_aton(offered_ip)),  # Requested IP Address
            (51, 4, cls.LEASE_TIME.to_bytes(4, 'big')),  # IP Address Lease Time
            # (52, 1, b'\x01\x0f'),  # Option Overload
            (53, 1, bytes([message_type])),  # DHCP Message Type
            (54, 4, socket.inet_aton(cls.SERVER_IP)),  # DHCP Server Identifier
            (55, 4, b'\x01\x03\x06\x0f'),  # Parameter Request List
            (56, len("Error message"), b"Error message"),  # Error Message
            (57, 2, (1500).to_bytes(2, 'big')),  # Maximum DHCP Message Size
            (58, 4, (cls.LEASE_TIME // 2).to_bytes(4, 'big')),  # Renewal (T1) Time Value
            (59, 4, int(cls.LEASE_TIME * 0.875).to_bytes(4, 'big')),  # Rebinding (T2) Time Value
            (60, len("PXEClient"), b"PXEClient"),  # Vendor Class Identifier
            (61, len(b'\x01' + chaddr), b'\x01' + chaddr),  # Client Identifier
            (66, len("TFTPServer"), b"TFTPServer"),  # TFTP Server Name
            (67, len("BootfileName"), b"BootfileName"),  # Bootfile Name
            (93, 2, (7).to_bytes(2, 'big')),  # Client System Architecture
            (94, 3, b"\x00\x00\x00"),  # Client Network Interface Identifier
            (97, 17, b"\x00" * 17),  # UUID/GUID-Based Client Identifier
        ]

        # Add each option to the packet
        for option in options:
            option_type, option_length, option_value = option
            packet += struct.pack(f"!BB{len(option_value)}s", option_type, option_length, option_value)

        # End Option (255)
        packet += struct.pack("B", 255)

        # Add padding to ensure the packet is aligned to a 4-byte boundary
        while len(packet) % 4 != 0:
            packet += b'\x00'

        return packet