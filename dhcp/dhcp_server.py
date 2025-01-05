import socket
import logging
import threading
import time
import os
from config.config import Config



class Server:
    # Server configuration
    SERVER_IP = socket.gethostbyname(socket.gethostname())
    SERVER_PORT = 67
    CLIENT_PORT = 68
    IP_POOL = [f"192.168.1.{i}" for i in range(10, 51)]  # IP pool from 192.168.1.10 to 192.168.1.50
    LEASES = {}  # Store client leases {MAC: IP}
    DISCOVERED_MACS = []    
    base_dir = os.path.dirname(__file__)
    ip_pool_dir = os.path.join(base_dir, "ip_pool.txt")
    available_ip_pool = []
    offered_ip = None
    blocked_MACS = [
        "17:11:03:23:12:02",
        "18:05:03:30:11:03"
    ]
    blocked_MAC = None
    server_running = False
    lease_lock = threading.Lock()
    LEASE_TIMERS = {}
    lease_thread = None


    @staticmethod
    def _write_ip_pool_to_file():
        """Write the IP pool to a file."""
        with open(Server.ip_pool_dir, "w") as file:
            for ip in Server.IP_POOL:
                file.write(ip + "\n")
    
    @staticmethod
    def _read_ip_pool():
        """Read the IP pool from a file."""
        with open(Server.ip_pool_dir, "r") as file:
            for line in file:
                Server.available_ip_pool.append(line.strip())
    
    @staticmethod
    def _write_ip_to_ip_pool_file(ip_address):
        """Write the IP pool to a file."""
        with open(Server.ip_pool_dir, "w") as file:
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
        lease_time = None

        # Parse options to find message type, requested IP, and lease time
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
            elif option_type == 51:  # Option 51: IP Address Lease Time
                lease_time = struct.unpack("!I", options[i + 2:i + 2 + length])[0]
            i += 2 + length

        return transaction_id, mac_addr, msg_type, requested_ip, lease_time

    @staticmethod
    def _lease_timer():
        """Thread to decrement lease times and reclaim expired IPs."""
        while Server.server_running:
            with Server.lease_lock:
                expired_macs = []
                for mac, remaining_time in Server.LEASE_TIMERS.items():
                    if remaining_time <= 0:
                        expired_macs.append(mac)
                    else:
                        Server.LEASE_TIMERS[mac] -= 1  # Decrement lease time
                
                # Reclaim expired leases
                for mac in expired_macs:
                    expired_ip = Server.LEASES.pop(mac, None)
                    if expired_ip:
                        Server.available_ip_pool.append(expired_ip)
                        print(f"Reclaimed expired IP {expired_ip} for MAC {mac}")
                        logging.info(f"Reclaimed expired IP {expired_ip} for MAC {mac}")
                    Server.LEASE_TIMERS.pop(mac, None)
                    Server._write_ip_to_ip_pool_file(Server.available_ip_pool)
            
            time.sleep(1)  # Wait 1 second before the next check



    @staticmethod
    def _handle_discover(transaction_id, mac_addr, sock, requested_ip, lease_time):
        """Handle DHCP Discover."""
        print(f"Handling Discover for MAC: {mac_addr}")
        logging.info(f"Handling Discover for MAC: {mac_addr}")
        # Assign the first available IP
        if mac_addr in Server.blocked_MACS:
            Server.blocked_MAC = mac_addr
            Server._send_dhcp_message(6, transaction_id, mac_addr, sock, requested_ip, lease_time)    
            return
        else:
            Server.blocked_MAC = None
        
        Server.offered_ip = next((ip for ip in Server.available_ip_pool if ip not in Server.LEASES.values()), None)
        
        Server.DISCOVERED_MACS.append(mac_addr)

        if Server.offered_ip:
            Server._send_dhcp_message(2, transaction_id, mac_addr, sock, requested_ip, lease_time)
            
        else:
            Server._send_dhcp_message(6, transaction_id, mac_addr, sock, requested_ip, lease_time)
        


    @staticmethod
    def _handle_NAK(msg_type, transaction_id, mac_addr, sock, lease_time):
        if Server.blocked_MAC is not None and mac_addr in Server.blocked_MAC:
            print(f"MAC {mac_addr} is blocked!")
            logging.warning(f"MAC {mac_addr} is blocked!")
            # Send DHCP NAK
            chaddr = bytes.fromhex(mac_addr.replace(":", ""))
            nak_packet = Config.create_dhcp_packet(msg_type, transaction_id, chaddr, "0.0.0.0", lease_time)  # 6 = NAK
            sock.sendto(nak_packet, ('<broadcast>', Server.CLIENT_PORT))
            print(f"Sent NAK to MAC {mac_addr}")
            logging.info(f"Sent NAK to MAC {mac_addr}")

        elif mac_addr not in Server.DISCOVERED_MACS:
            print(f"No DISCOVER message found for MAC {mac_addr}")
            logging.warning(f"No DISCOVER message found for MAC {mac_addr}")
            print(f"Sent NAK to MAC {mac_addr}")
            logging.info(f"Sent NAK to MAC {mac_addr}")
            # Send DHCP NAK
            chaddr = bytes.fromhex(mac_addr.replace(":", ""))
            nak_packet = Config.create_dhcp_packet(msg_type, transaction_id, chaddr, "0.0.0.0", lease_time)

        elif lease_time > Config.LEASE_TIME:
            print(f"Lease time is greater than the maximum lease time")
            logging.warning(f"Lease time is greater than the maximum lease time")
            # Send DHCP NAK
            chaddr = bytes.fromhex(mac_addr.replace(":", ""))
            nak_packet = Config.create_dhcp_packet(msg_type, transaction_id, chaddr, "0.0.0.0", lease_time)

        elif not Server.offered_ip:
            print("No available IPs in the pool!")
            logging.warning("No available IPs in the pool!")
            print(f"Sent NAK to MAC {mac_addr}")
            logging.info(f"Sent NAK to MAC {mac_addr}")
            # Send DHCP NAK
            chaddr = bytes.fromhex(mac_addr.replace(":", ""))
            nak_packet = Config.create_dhcp_packet(msg_type, transaction_id, chaddr, "0.0.0.0", lease_time)  # 6 = NAK
            sock.sendto(nak_packet, ('<broadcast>', Server.CLIENT_PORT))
            print(f"Sent NAK to MAC {mac_addr}")
            logging.info(f"Sent NAK to MAC {mac_addr}")

    @staticmethod
    def _handle_offer(msg_type, sock, requested_ip, transaction_id, mac_addr, lease_time):
        
        if requested_ip not in Server.available_ip_pool:
            requested_ip = None
        
            
        Server.offered_ip = Server.offered_ip if requested_ip is None else requested_ip
        
        # Send DHCP Offer
        chaddr = bytes.fromhex(mac_addr.replace(":", ""))
        packet = Config.create_dhcp_packet(msg_type, transaction_id, chaddr, Server.offered_ip, lease_time)  # 2 = Offer
        sock.sendto(packet, ('<broadcast>', Server.CLIENT_PORT))
        print(f"Offered IP {Server.offered_ip} to MAC {mac_addr}")
        logging.info(f"Offered IP {Server.offered_ip} to MAC {mac_addr}")
        

    @staticmethod
    def _handle_request(transaction_id, mac_addr, sock, requested_ip, lease_time):
        """Handle DHCP Request."""
        print(f"Handling Request for MAC: {mac_addr}")
        logging.info(f"Handling Request for MAC: {mac_addr}")
        if mac_addr not in Server.DISCOVERED_MACS:
            Server._send_dhcp_message(6, transaction_id, mac_addr, sock, requested_ip, lease_time)
            return

        if requested_ip not in Server.available_ip_pool:
            requested_ip = None
        # Get the offered IP
        Server.offered_ip = Server.LEASES.get(mac_addr) if requested_ip is None else requested_ip
        if not Server.offered_ip:
            print(f"No offered IP for MAC {mac_addr}")
            logging.warning(f"No offered IP for MAC {mac_addr}")
            Server._send_dhcp_message(6, transaction_id, mac_addr, sock, requested_ip, lease_time)
        elif lease_time and lease_time > Config.LEASE_TIME:
            Server._send_dhcp_message(6, transaction_id, mac_addr, sock, requested_ip, lease_time)
        else:
            Server._send_dhcp_message(5, transaction_id, mac_addr, sock, requested_ip, lease_time)
        
    
    @staticmethod
    def _handle_ACK(msg_type, transaction_id, mac_addr, sock, lease_time):
        # Send DHCP Ack
        chaddr = bytes.fromhex(mac_addr.replace(":", ""))
        packet = Config.create_dhcp_packet(msg_type, transaction_id, chaddr, Server.offered_ip, lease_time)  # 5 = Ack
        
        if Server.offered_ip not in Server.LEASES.values():
            sock.sendto(packet, ('<broadcast>', Server.CLIENT_PORT))
        else:
            sock.sendto(packet, (Server.offered_ip, Server.CLIENT_PORT))
            
        if not Server.offered_ip == "0.0.0.0":
            Server.LEASES[mac_addr] = Server.offered_ip
            Server.LEASE_TIMERS[mac_addr] = lease_time
        print(f"Acknowledged IP {Server.offered_ip} for MAC {mac_addr}")
        logging.info(f"Acknowledged IP {Server.offered_ip} for MAC {mac_addr}")
        try:
            Server.available_ip_pool.remove(Server.offered_ip)
        except:
            pass
        Server._write_ip_to_ip_pool_file(Server.available_ip_pool)
        
        if lease_time is None:
            lease_time = Config.LEASE_TIME
        
        with Server.lease_lock:
            Server.LEASE_TIMERS[mac_addr] = lease_time

    @staticmethod 
    def _handle_dhcp_release(mac_addr):
        """Handle DHCP Release."""
        print(f"Handling Release for MAC: {mac_addr}")
        logging.info(f"Handling Release for MAC: {mac_addr}")
        ip_address = Server.LEASES.get(mac_addr)
        if ip_address:
            Server.LEASES.pop(mac_addr)
            Server.available_ip_pool.append(ip_address)
            Server._write_ip_to_ip_pool_file(Server.available_ip_pool)
            print(f"Released IP {ip_address} for MAC {mac_addr}")
            logging.info(f"Released IP {ip_address} for MAC {mac_addr}")
    
    @staticmethod
    def _handle_decline(mac_addr):
        """Handle DHCP Decline."""
        print(f"Handling Decline for MAC: {mac_addr}")
        logging.info(f"Handling Decline for MAC: {mac_addr}")

        print(f"Declined IP {Server.offered_ip} for MAC {mac_addr}")
        logging.info(f"Declined IP {Server.offered_ip} for MAC {mac_addr}")

    @staticmethod
    def _handle_dhcp_inform(transaction_id , mac_addr, sock, requested_ip, lease_time):
        """Handle DHCP Inform."""
        print(f"Handling INFORM for MAC: {mac_addr}")
        logging.info(f"Handling INFORM for MAC: {mac_addr}")
        Server.offered_ip = "0.0.0.0"
        Server._send_dhcp_message(5, transaction_id, mac_addr, sock, Server.SERVER_IP, lease_time)
        
            

    
    @staticmethod
    def _handle_dhcp_message(data, sock):
        """Parse DHCP message and determine the phase."""
        # Parse the received packet
        transaction_id, mac_addr, msg_type, requested_ip, lease_time = Server._parse_dhcp_packet(data)
        if msg_type == 1:  # Discover   
            Server._handle_discover(transaction_id,mac_addr, sock, requested_ip, lease_time)
        
        elif msg_type == 3:  # Request
            Server._handle_request(transaction_id, mac_addr, sock, requested_ip, lease_time)
        
        elif msg_type == 4:  # Decline
            Server._handle_decline(mac_addr)
        
        elif msg_type == 7: # Handling DHCP Release
            Server._handle_dhcp_release(mac_addr)

        elif msg_type == 8: # Handling DHCP Inform
            Server._handle_dhcp_inform(transaction_id, mac_addr, sock, requested_ip, lease_time)
            
        else:
            print("Unknown DHCP message type")
            logging.warning("Unknown DHCP message type")
    
    @staticmethod
    def _send_dhcp_message(msg_type, transaction_id, mac_addr, sock, requested_ip, lease_time):
        if msg_type == 2: # Offer
            Server._handle_offer(msg_type, sock, requested_ip, transaction_id, mac_addr, lease_time)
        
        elif msg_type == 5: # Ack
            Server._handle_ACK(msg_type, transaction_id, mac_addr, sock, lease_time)
        
        elif msg_type == 6: # NAK
            Server._handle_NAK(msg_type, transaction_id, mac_addr, sock, lease_time)
        
        else:
            print("Unknown DHCP message type")
            logging.warning("Unknown DHCP message type")

    @staticmethod
    def start_dhcp_server(args):
        """Start the DHCP server."""
        Config.LEASE_TIME = int(args.lease_time) if args.lease_time else Config.LEASE_TIME
        Server.IP_POOL = Server.IP_POOL if not args.NAK else []

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.bind(('0.0.0.0', Server.SERVER_PORT))  # Bind to all available interfaces

        print(f"DHCP server running on IP({Server.SERVER_IP}) PORT({Server.SERVER_PORT})")
        logging.info(f"DHCP server running on IP({Server.SERVER_IP}) PORT({Server.SERVER_PORT})")

        Server._write_ip_pool_to_file()
        Server._read_ip_pool()

        Server.server_running = True  # Set the server running flag
        Server.lease_thread = threading.Thread(target=Server._lease_timer)
        Server.lease_thread.start()
        try:
            while Server.server_running:
                try:
                    sock.settimeout(1.0)  # Add a timeout to periodically check the flag
                    data, address = sock.recvfrom(1024)
                    if not Server.server_running:
                        break  # Stop processing if the server is no longer running
                    print(f"Received packet from {address}")
                    logging.info(f"Received packet from {address}")
                    Server._handle_dhcp_message(data, sock)
                except socket.timeout:
                    continue  # Timeout occurred, check the running flag again
                except Exception as e:
                    print(f"Error: {e}")
                    logging.error(f"Error: {e}")
        finally:
            print("Shutting down the server...")
            logging.info("Shutting down the server...")
            sock.close()
            Server.server_running = False
            logging.info("Shutted Down")

    @staticmethod
    def stop():
        """Stop the DHCP server."""
        Server.server_running = False
        if Server.lease_thread:
            Server.lease_thread.join()