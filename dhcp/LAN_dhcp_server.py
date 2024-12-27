import socket
import struct

# Constants
SERVER_IP = "192.168.1.1"
SUBNET_MASK = "255.255.255.0"
DNS_SERVER = SERVER_IP
LEASE_TIME = 86400
MAGIC_COOKIE = b'\x63\x82\x53\x63'

def create_dhcp_packet(message_type, xid, yiaddr, chaddr):
    """Create a DHCP packet."""
    packet = struct.pack(
        '!BBBBIHHIIII16s192x',
        2, 1, 6, 0, xid, 0, 0x8000,
        0, struct.unpack("!I", socket.inet_aton(yiaddr))[0],
        struct.unpack("!I", socket.inet_aton(SERVER_IP))[0], 0,
        chaddr.ljust(16, b'\x00')
    )

    # Add Magic Cookie
    packet += MAGIC_COOKIE

    # DHCP Options
    options = [
        (53, 1, bytes([message_type])),
        (54, 4, socket.inet_aton(SERVER_IP)),
        (51, 4, LEASE_TIME.to_bytes(4, 'big')),
        (1, 4, socket.inet_aton(SUBNET_MASK)),
        (3, 4, socket.inet_aton(SERVER_IP)),
        (6, 4, socket.inet_aton(DNS_SERVER)),
    ]

    for option in options:
        option_type, option_length, option_value = option
        packet += struct.pack(f"!BB{len(option_value)}s", option_type, option_length, option_value)

    packet += struct.pack("B", 255)  # End Option
    while len(packet) % 4 != 0:
        packet += b'\x00'

    return packet

class LAN_Server:
    # Server configuration
    SERVER_IP = "192.168.1.1"
    SERVER_PORT = 67
    CLIENT_PORT = 68
    IP_POOL = [f"192.168.1.{i}" for i in range(10, 51)]  # IP pool from 192.168.1.10 to 192.168.1.50
    LEASES = {}  # Store client leases {MAC: IP}

    @staticmethod
    def _parse_dhcp_packet(data):
        """Parse the incoming DHCP packet."""
        transaction_id = struct.unpack("!I", data[4:8])[0]
        mac_addr = ':'.join(f"{b:02x}" for b in data[28:34])
        options = data[240:]  # Options start at byte 240
        msg_type = None

        # Parse options to find message type
        i = 0
        while i < len(options):
            if options[i] == 53:  # Option 53: Message Type
                msg_type = options[i + 2]
                break
            i += 2 + options[i + 1]
        return transaction_id, mac_addr, msg_type

    @staticmethod
    def _handle_discover(transaction_id, mac_addr, sock):
        """Handle DHCP Discover."""
        print(f"Handling Discover for MAC: {mac_addr}")

        # Assign the first available IP
        offered_ip = next((ip for ip in LAN_Server.IP_POOL if ip not in LAN_Server.LEASES.values()), None)
        if not offered_ip:
            print("No available IPs in the pool!")
            return

        # Send DHCP Offer
        chaddr = bytes.fromhex(mac_addr.replace(":", ""))
        packet = create_dhcp_packet(2, transaction_id, offered_ip, chaddr)  # 2 = Offer
        LAN_Server.LEASES[mac_addr] = offered_ip
        sock.sendto(packet, ('<broadcast>', LAN_Server.CLIENT_PORT))
        print(f"Offered IP {offered_ip} to MAC {mac_addr}")

    @staticmethod
    def _handle_request(transaction_id, mac_addr, sock):
        """Handle DHCP Request."""
        print(f"Handling Request for MAC: {mac_addr}")

        # Get the offered IP
        offered_ip = LAN_Server.LEASES.get(mac_addr)
        if not offered_ip:
            print(f"No offered IP for MAC {mac_addr}")
            return

        # Send DHCP Ack
        chaddr = bytes.fromhex(mac_addr.replace(":", ""))
        packet = create_dhcp_packet(5, transaction_id, offered_ip, chaddr)  # 5 = Ack
        sock.sendto(packet, (offered_ip, LAN_Server.CLIENT_PORT))
        print(f"Acknowledged IP {offered_ip} for MAC {mac_addr}")

    @staticmethod
    def _handle_dhcp_message(data, sock):
        """Parse DHCP message and determine the phase."""
        # Parse the received packet
        transaction_id, mac_addr, msg_type = LAN_Server._parse_dhcp_packet(data)
        if msg_type == 1:  # Discover   
            LAN_Server._handle_discover(transaction_id, mac_addr, sock)
        elif msg_type == 3:  # Request
            LAN_Server._handle_request(transaction_id, mac_addr, sock)

    @staticmethod
    def start_dhcp_server():
        """Start the DHCP server."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.bind(('0.0.0.0', LAN_Server.SERVER_PORT))  # Bind to all available interfaces
        print(f"DHCP server running on {LAN_Server.SERVER_IP}:{LAN_Server.SERVER_PORT}")

        while True:
            try:
                data, address = sock.recvfrom(1024)
                print(f"Received packet from {address}")
                LAN_Server._handle_dhcp_message(data, sock)
            except Exception as e:
                print(f"Error: {e}")
