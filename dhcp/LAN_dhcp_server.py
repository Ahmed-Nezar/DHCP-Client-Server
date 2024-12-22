import socket
import struct
import threading
import time

class LAN_Server:
    lease_table = {}  # Stores current leases
    ip_pool = ["192.168.1.100", "192.168.1.101", "192.168.1.102"]  # Example pool
    lease_time = 3600  # Lease time in seconds
    blacklist_macs = ["18:05:03:30:11:03"]

    @staticmethod
    def parse_dhcp_packet(data):
        """Parse DHCP Discover or Request messages."""
        try:
            transaction_id = struct.unpack("!I", data[4:8])[0]
            client_mac = ":".join(f"{b:02x}" for b in data[28:34])
            print(f"Parsed DHCP packet: TID={transaction_id}, MAC={client_mac}")
            return transaction_id, client_mac
        except Exception as e:
            print(f"Error parsing DHCP packet: {e}")
            return None, None

    @staticmethod
    def create_dhcp_offer(transaction_id, client_mac, offered_ip):
        """Create a DHCP Offer message."""
        offer = struct.pack(
            '!4B I 4x 4s 4s 4s 16s 64s 128s',
            2,  # BOOTREPLY
            1,  # Ethernet
            6,  # MAC address length
            0,  # Hops
            transaction_id,  # Transaction ID
            socket.inet_aton(offered_ip),  # Your IP
            socket.inet_aton("192.168.1.1"),  # Server IP
            socket.inet_aton("0.0.0.0"),  # Gateway IP
            bytes.fromhex(client_mac.replace(":", "")) + b"\x00" * 10,  # Client MAC (padded to 16 bytes)
            b"",  # Server name (16 bytes)
            b""   # Boot file name (64 bytes)
        )
        # Add DHCP options (53 = DHCP message type, etc.)
        options = (
            b"\x63\x82\x53\x63"  # Magic cookie
            + b"\x35\x01\x02"  # Option 53 (DHCP Offer)
            + b"\x33\x04" + struct.pack("!I", LAN_Server.lease_time)  # Lease time
            + b"\xff"  # End option
        )
        return offer + options



    @staticmethod
    def handle_discover(data, server_socket, client_address):
        transaction_id, client_mac = LAN_Server.parse_dhcp_packet(data)
        if not transaction_id or not client_mac:
            return

        # Blacklist check
        if client_mac in LAN_Server.blacklist_macs:
            print(f"Blocked MAC: {client_mac}")
            return

        # Find an available IP
        for ip in LAN_Server.ip_pool:
            if ip not in [entry[0] for entry in LAN_Server.lease_table.values()]:
                offered_ip = ip
                break
        else:
            print("No available IP addresses.")
            return

        # Send DHCP Offer
        offer_packet = LAN_Server.create_dhcp_offer(transaction_id, client_mac, offered_ip)
        server_socket.sendto(offer_packet, ("255.255.255.255", 68))
        print(f"Sent DHCP Offer: {offered_ip} to {client_address} (MAC: {client_mac})")

    @staticmethod
    def start_server():
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        server_socket.bind(("", 67))

        print("DHCP Server running on port 67...")

        while True:
            data, client_address = server_socket.recvfrom(1024)
            print(f"Received data from {client_address}")

            if data[242:243] == b"\x01":  # DHCP Discover
                LAN_Server.handle_discover(data, server_socket, client_address)
            # Add other cases for Request, Release, etc., as needed.
