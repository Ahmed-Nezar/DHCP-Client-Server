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
    def create_dhcp_packet(cls, message_type, xid, yiaddr, chaddr):
        """Create a DHCP packet."""
        packet = struct.pack(
            '!BBBBIHHIIII16s192x',
            2, 1, 6, 0, xid, 0, 0x8000,
            0, struct.unpack("!I", socket.inet_aton(yiaddr))[0],
            struct.unpack("!I", socket.inet_aton(cls.SERVER_IP))[0], 0,
            chaddr.ljust(16, b'\x00')
        )

        # Add Magic Cookie
        packet += cls.MAGIC_COOKIE

        # DHCP Options
        options = [
            (53, 1, bytes([message_type])),
            (54, 4, socket.inet_aton(cls.SERVER_IP)),
            (51, 4, cls.LEASE_TIME.to_bytes(4, 'big')),
            (1, 4, socket.inet_aton(cls.SUBNET_MASK)),
            (3, 4, socket.inet_aton(cls.SERVER_IP)),
            (6, 4, socket.inet_aton(cls.DNS_SERVER)),
        ]

        for option in options:
            option_type, option_length, option_value = option
            packet += struct.pack(f"!BB{len(option_value)}s", option_type, option_length, option_value)

        packet += struct.pack("B", 255)  # End Option
        while len(packet) % 4 != 0:
            packet += b'\x00'

        return packet