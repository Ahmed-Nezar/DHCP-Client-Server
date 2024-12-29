import socket
import threading
import time
import signal
from dhcp.utils import get_valid_ipv4, DHCPMessage

class DHCPServer:
    def __init__(self, ip_pool):
        self.ip_pool = ip_pool
        self.server_ip = get_valid_ipv4()
        self.leases = {}
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((self.server_ip, 67))
        self.blacklist_macs = [
            "18:05:03:30:11:03",
            "17:11:03:23:12:02"
        ]
        self.tids = set()

    def handle_discover(self, addr, discover_msg):
        
        for option, value in discover_msg.options.items():
            print(f"Option {option}: {value}")
            print(f"Option using get option {option}: {discover_msg.get_option(option)}, type: {type(discover_msg.get_option(option))}")


        client_id = discover_msg.get_option(61)
        self.tids.add(discover_msg.tid)
        
        # if client_id is None:
        #     print("Client Identifier (Option 61) is missing. Ignoring Discover message.")
        #     return
        print(f"Received DHCP Discover message from Client: {client_id}, TID: {discover_msg.tid}")

        if client_id in self.blacklist_macs:
            nak_msg = DHCPMessage(6)
            self.sock.sendto(nak_msg.to_json().encode(), addr)
            print(f"Blacklisted MAC address: {client_id}. Sending NAK...")
            return

        if len(self.ip_pool) == 0:
            print("No available IP addresses. Sending NAK...")
            nak_msg = DHCPMessage(6)
            self.sock.sendto(nak_msg.to_json().encode(), addr)
            return


        offered_ip = self.ip_pool.pop(0)
        offer_msg = DHCPMessage(2)
        offer_msg.set_option(53, 2)
        offer_msg.set_option(54, self.server_ip)
        offer_msg.set_option(1, "255.255.255.0")
        offer_msg.set_option(3, self.server_ip)
        offer_msg.set_option(51, 3600)
        offer_msg.set_option(50, offered_ip)

        print(f"Offering IP: {offered_ip} to Client: {client_id}")
        self.sock.sendto(offer_msg.to_json().encode(), addr)

    def handle_request(self, addr, request_msg):
        print("Received DHCP Request message...")


        requested_ip = request_msg.get_option(50)
        client_id = request_msg.get_option(61)

        if requested_ip not in self.leases and requested_ip in self.ip_pool:
            self.leases[client_id] = requested_ip
            self.ip_pool.remove(requested_ip)

        ack_msg = DHCPMessage(5)
        ack_msg.set_option(53, 5)
        ack_msg.set_option(54, self.server_ip)
        ack_msg.set_option(1, "255.255.255.0")
        ack_msg.set_option(3, self.server_ip)
        ack_msg.set_option(51, 3600)
        ack_msg.set_option(50, requested_ip)
        print(f"Sending ACK for IP: {requested_ip} to Client: {client_id}")
        self.sock.sendto(ack_msg.to_json().encode(), addr)

    def shutdown(self, signum, frame):
        print("Shutting down DHCP Server...")
        self.sock.close()
        exit(0)
    def listen(self):
        print("DHCP Server is running and listening on port 67...")
        while True:
            try:
                data, addr = self.sock.recvfrom(1024)
                message = DHCPMessage.from_json(data=data.decode())
                if message.message_type == 1:
                    self.handle_discover(addr, message)
                elif message.message_type == 3:
                    self.handle_request(addr, message)
                # signal.signal(signal.SIGINT, self.shutdown)
                # signal.signal(signal.SIGTERM, self.shutdown)
            except Exception as e:
                print(f"Error: {e}")
                continue

class Server:
    
    lease_table = {}  # Stores the current leases
    blacklist_macs = [
        "18:05:03:30:11:03"
    ]
    discover_tids = set()  # Stores TIDs that have sent a Discover message
    
    @staticmethod
    def _handle_discover(server_socket, client_address, ip_pool, lease_time, tid, mac_address):
        print(f"Received DHCP Discover message with TID: {tid} and MAC address: {mac_address}")

        if mac_address in Server.blacklist_macs:
            nak_message = f"DHCP Nak Blacklisted MAC {tid}".encode()
            server_socket.sendto(nak_message, client_address)
            print(f"Sent DHCP Nak to {client_address}: Blacklisted MAC with TID: {tid}")
            return
        
        for value in Server.lease_table.values():
            if value[2] == mac_address:
                nak_message = f"DHCP Nak MAC Already Leased {tid}".encode()
                server_socket.sendto(nak_message, client_address)
                print(f"Sent DHCP Nak to {client_address}: MAC already leased with TID: {tid}")
                return

        available_ip = None
        for ip in ip_pool:
            if ip not in [entry[0] for entry in Server.lease_table.values()]:
                available_ip = ip
                break

        if available_ip is None:
            nak_message = f"DHCP Nak No Available IPs {tid}".encode()
            server_socket.sendto(nak_message, client_address)
            print(f"Sent DHCP Nak to {client_address}: No available IPs with TID: {tid}")
            return
        
        # Offer the available IP
        c_address = ("0.0.0.0", 68)
        offer_message = f"DHCPOffer {available_ip} {tid} LeaseTime {lease_time} {client_address}".encode()
        server_socket.sendto(offer_message, client_address)
        print(f"Sent DHCP Offer with IP: {available_ip} to {c_address} with TID: {tid} and MAC: {mac_address}")

        # Add TID to discover_tids set
        Server.discover_tids.add(tid)

    @staticmethod
    def _handle_request(server_socket, client_address, data, ip_pool, lease_time):
        parts = data.decode().split(" ")
        requested_ip = parts[2]
        tid = parts[3]
        mac_address = parts[4]
        c_address = ("0.0.0.0", 68)
        print(f"Received DHCP Request for IP: {requested_ip} with TID: {tid} and MAC address: {mac_address}")

        # Check if the TID is in the discover_tids set
        if tid not in Server.discover_tids:
            nak_message = f"DHCP Nak No Prior Discover {tid}".encode()
            server_socket.sendto(nak_message, client_address)
            print(f"Sent DHCP Nak to {client_address}: No prior Discover message with TID: {tid}")
            return

        if requested_ip not in ip_pool:
            nak_message = f"DHCP Nak Invalid IP {tid}".encode()
            server_socket.sendto(nak_message, client_address)
            print(f"Sent DHCP Nak to {c_address}: Invalid IP requested with TID: {tid}")
            return

        # Handle DHCP Decline
        if parts[0] == "DHCP" and parts[1] == "Decline":
            print(f"Received DHCP Decline message with TID: {tid}, MAC address: {mac_address}, and desired lease time: {lease_time}")
            if tid in Server.lease_table:
                del Server.lease_table[tid]
                print(f"Removed declined offer for TID: {tid} and MAC address: {mac_address}")
            return
        
        # Existing handling for DHCP Request
        lease_entry = Server.lease_table.get(tid)
        if lease_entry:
            leased_ip, _, _ = lease_entry
            if leased_ip == requested_ip:
                Server.lease_table[tid] = (requested_ip, lease_time, mac_address)
                ack_message = f"DHCP Acknowledge {requested_ip} {tid} LeaseTime {lease_time} {mac_address}".encode()
                server_socket.sendto(ack_message, client_address)
                print(f"Sent DHCP Acknowledge for IP: {requested_ip} to {requested_ip} with TID: {tid} and MAC: {mac_address}")
                return
            else:
                nak_message = f"DHCP Nak IP Mismatch {tid}".encode()
                server_socket.sendto(nak_message, client_address)
                print(f"Sent DHCP Nak to {client_address}: IP mismatch with TID: {tid}")
                return

        # Handle New Lease Request
        if any(entry[0] == requested_ip for entry in Server.lease_table.values()):
            nak_message = f"DHCP Nak IP Already Leased {tid}".encode()
            server_socket.sendto(nak_message, client_address)
            print(f"Sent DHCP Nak to {c_address}: IP already leased with TID: {tid}")
            return

        Server.lease_table[tid] = (requested_ip, lease_time, mac_address)
        ack_message = f"DHCP Acknowledge {requested_ip} {tid} LeaseTime {lease_time} {mac_address}".encode()
        server_socket.sendto(ack_message, client_address)
        print(f"Sent DHCP Acknowledge for IP: {requested_ip} to {requested_ip} with TID: {tid} and MAC: {mac_address}")

    @staticmethod
    def _decrement_lease_times():
        while True:
            time.sleep(1)
            for tid, entry in list(Server.lease_table.items()):
                lease_time = entry[1]
                if lease_time <= 0:
                    del Server.lease_table[tid]
                else:
                    Server.lease_table[tid] = (entry[0], lease_time - 1, entry[2])
            if Server.lease_table:
                print(f"Lease Table: {Server.lease_table}")
    
    @staticmethod
    def start_server():
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        ipv4_address = get_valid_ipv4()
        server_address = (ipv4_address, 67)
        server_socket.bind(server_address)

        print("DHCP Server is running and listening on port 67...")

        ip_pool = ["192.168.1." + str(i) for i in range(100, 103)]
        lease_time = 10  # Lease time in seconds
        
        lease_thread = threading.Thread(target=Server._decrement_lease_times)
        lease_thread.daemon = True 
        lease_thread.start()

        while True:
            data, client_address = server_socket.recvfrom(1024)
            parts = data.decode(errors='ignore').split(" ")

            # Handling DHCP Discover message
            if parts[0] == "DHCP" and parts[1] == "Discover":
                tid = parts[2]
                mac_address = parts[3]
                Server._handle_discover(server_socket, client_address, ip_pool, lease_time, tid, mac_address)

            # Handling DHCP Request message
            elif parts[0] == "DHCP" and parts[1] == "Request":
                Server._handle_request(server_socket, client_address, data, ip_pool, lease_time)

            # Handling DHCP Decline message
            elif parts[0] == "DHCP" and parts[1] == "Decline":
                tid = parts[3]
                mac_address = parts[4]
                desired_lease_time = parts[5]
                print(f"Received DHCP Decline message with TID: {tid}, MAC address: {mac_address}, and desired lease time: {desired_lease_time}")
                if tid in Server.lease_table:
                    del Server.lease_table[tid]
                    print(f"Removed declined offer for TID: {tid} and MAC address: {mac_address}")

            # Handling DHCP Release message
            elif parts[0] == "DHCP" and parts[1] == "Release":
                offered_ip = parts[2]  # Extract the offered IP
                tid = parts[3]         # Extract the TID
                mac_address = parts[4] # Extract the MAC address
                print(f"Received DHCP Release for IP: {offered_ip}, TID: {tid}, MAC: {mac_address}")

                # Check if the TID exists in the lease table
                if tid in Server.lease_table:
                    leased_ip, _, leased_mac = Server.lease_table[tid]
                    if leased_ip == offered_ip and leased_mac == mac_address:
                        del Server.lease_table[tid]
                        print(f"Released IP: {leased_ip} for TID: {tid} and MAC: {mac_address}")
                    else:
                        print(f"Mismatch for TID: {tid}. Expected IP: {leased_ip}, MAC: {leased_mac}, Received IP: {offered_ip}, MAC: {mac_address}")
                else:
                    print(f"No lease found for TID: {tid}")

# Print current lease table for debugging
# print(f"Current Lease Table: {Server.lease_table}")
# print('>' * 40)
