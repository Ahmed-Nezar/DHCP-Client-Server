import socket
import logging
import os
from ..config.config import Config



class LAN_Server:
    # Server configuration
    SERVER_IP = "192.168.1.1"
    SERVER_PORT = 67
    CLIENT_PORT = 68
    IP_POOL = [f"192.168.1.{i}" for i in range(10, 51)]  # IP pool from 192.168.1.10 to 192.168.1.50
    LEASES = {}  # Store client leases {MAC: IP}
    base_dir = os.path.dirname(__file__)
    ip_pool_dir = os.path.join(base_dir, "ip_pool.txt")
    available_ip_pool = []


    @staticmethod
    def _write_ip_pool_to_file():
        """Write the IP pool to a file."""
        with open(LAN_Server.ip_pool_dir, "w") as file:
            for ip in LAN_Server.IP_POOL:
                file.write(ip + "\n")
    
    @staticmethod
    def _read_ip_pool():
        """Read the IP pool from a file."""
        with open(LAN_Server.ip_pool_dir, "r") as file:
            for line in file:
                LAN_Server.available_ip_pool.append(line.strip())
    
    @staticmethod
    def _write_ip_to_ip_pool_file(ip_address):
        """Write the IP pool to a file."""
        with open(LAN_Server.ip_pool_dir, "w") as file:
            for ip in ip_address:
                file.write(ip + "\n")
            
    
    @staticmethod
    def _parse_dhcp_packet(data):
        """Parse the incoming DHCP packet."""
        import struct

        # Extract transaction ID and MAC address
        transaction_id = struct.unpack("!I", data[4:8])[0]
        mac_addr = ':'.join(f"{b:02x}" for b in data[28:34])
        options = data[240:]  # Options start at byte 240

        msg_type = None
        requested_ip = None

        # Parse options to find message type and requested IP
        i = 0
        while i < len(options):
            option_type = options[i]
            if option_type == 255:  # Option 255: End of options
                break
            length = options[i + 1]
            if option_type == 53:  # Option 53: DHCP Message Type
                msg_type = options[i + 2]
            elif option_type == 50:  # Option 50: Requested IP Address
                requested_ip = '.'.join(map(str, options[i + 2:i + 2 + length]))
            i += 2 + length

        return transaction_id, mac_addr, msg_type, requested_ip


    @staticmethod
    def _handle_discover(transaction_id, mac_addr, sock, requested_ip):
        """Handle DHCP Discover."""
        print(f"Handling Discover for MAC: {mac_addr}")
        logging.info(f"Handling Discover for MAC: {mac_addr}")

        # Assign the first available IP
        offered_ip = next((ip for ip in LAN_Server.available_ip_pool if ip not in LAN_Server.LEASES.values()), None)
        
        if not offered_ip:
            print("No available IPs in the pool!")
            logging.warning("No available IPs in the pool!")
            return

        if requested_ip not in LAN_Server.available_ip_pool:
            requested_ip = None
            
        offered_ip = offered_ip if requested_ip is None else requested_ip
        
        # Send DHCP Offer
        chaddr = bytes.fromhex(mac_addr.replace(":", ""))
        packet = Config.create_dhcp_packet(2, transaction_id, offered_ip, chaddr)  # 2 = Offer
        sock.sendto(packet, ('<broadcast>', LAN_Server.CLIENT_PORT))
        print(f"Offered IP {offered_ip} to MAC {mac_addr}")
        logging.info(f"Offered IP {offered_ip} to MAC {mac_addr}")

    @staticmethod
    def _handle_request(transaction_id, mac_addr, sock, requested_ip):
        """Handle DHCP Request."""
        print(f"Handling Request for MAC: {mac_addr}")
        logging.info(f"Handling Request for MAC: {mac_addr}")

        if requested_ip not in LAN_Server.available_ip_pool:
            requested_ip = None
        # Get the offered IP
        offered_ip = LAN_Server.LEASES.get(mac_addr) if requested_ip is None else requested_ip
        if not offered_ip:
            print(f"No offered IP for MAC {mac_addr}")
            logging.warning(f"No offered IP for MAC {mac_addr}")
            return

        # Send DHCP Ack
        chaddr = bytes.fromhex(mac_addr.replace(":", ""))
        packet = Config.create_dhcp_packet(5, transaction_id, offered_ip, chaddr)  # 5 = Ack
        if offered_ip not in LAN_Server.LEASES.values():
            sock.sendto(packet, ('<broadcast>', LAN_Server.CLIENT_PORT))
        else:
            sock.sendto(packet, (offered_ip, LAN_Server.CLIENT_PORT))
            
        LAN_Server.LEASES[mac_addr] = offered_ip
        print(f"Acknowledged IP {offered_ip} for MAC {mac_addr}")
        logging.info(f"Acknowledged IP {offered_ip} for MAC {mac_addr}")
        try:
            LAN_Server.available_ip_pool.remove(offered_ip)
        except:
            pass
        LAN_Server._write_ip_to_ip_pool_file(LAN_Server.available_ip_pool)

    @staticmethod 
    def _handle_dhcp_release(mac_addr):
        """Handle DHCP Release."""
        print(f"Handling Release for MAC: {mac_addr}")
        logging.info(f"Handling Release for MAC: {mac_addr}")
        ip_address = LAN_Server.LEASES.get(mac_addr)
        if ip_address:
            LAN_Server.LEASES.pop(mac_addr)
            LAN_Server.available_ip_pool.append(ip_address)
            LAN_Server._write_ip_to_ip_pool_file(LAN_Server.available_ip_pool)
            print(f"Released IP {ip_address} for MAC {mac_addr}")
            logging.info(f"Released IP {ip_address} for MAC {mac_addr}")
    
    @staticmethod
    def _handle_dhcp_message(data, sock):
        """Parse DHCP message and determine the phase."""
        # Parse the received packet
        transaction_id, mac_addr, msg_type, requested_ip = LAN_Server._parse_dhcp_packet(data)
        if msg_type == 1:  # Discover   
            LAN_Server._handle_discover(transaction_id, mac_addr, sock, requested_ip)
        elif msg_type == 3:  # Request
            LAN_Server._handle_request(transaction_id, mac_addr, sock, requested_ip)
        elif msg_type == 7: # Handling DHCP Release
            LAN_Server._handle_dhcp_release(mac_addr)
        else:
            print("Unknown DHCP message type")
            logging.warning("Unknown DHCP message type")

    @staticmethod
    def start_dhcp_server(args):
        """Start the DHCP server."""
        Config.LEASE_TIME = args.lease_time if args.lease_time else Config.LEASE_TIME
        LAN_Server.IP_POOL = LAN_Server.IP_POOL if not args.NAK else []
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.bind(('0.0.0.0', LAN_Server.SERVER_PORT))  # Bind to all available interfaces
        print(f"DHCP server running on IP({LAN_Server.SERVER_IP}) PORT({LAN_Server.SERVER_PORT})")
        logging.info(f"DHCP server running on IP({LAN_Server.SERVER_IP}) PORT({LAN_Server.SERVER_PORT})")
        LAN_Server._write_ip_pool_to_file()
        LAN_Server._read_ip_pool()

        while True:
            try:
                data, address = sock.recvfrom(1024)
                print(f"Received packet from {address}")
                logging.info(f"Received packet from {address}")
                LAN_Server._handle_dhcp_message(data, sock)
            except Exception as e:
                print(f"Error: {e}")
                logging.error(f"Error: {e}")
