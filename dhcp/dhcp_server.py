import socket
import threading
import time
from dhcp.utils import get_valid_ipv4

class Server:
    
    lease_table = {}  # Stores the current leases
    blacklist_macs = [
        "18:05:03:30:11:03"
    ]
    
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
            # If no IPs are available, send a DHCP Nak
            nak_message = f"DHCP Nak No Available IPs {tid}".encode()
            server_socket.sendto(nak_message, client_address)
            print(f"Sent DHCP Nak to {client_address}: No available IPs with TID: {tid}")
            return
        
        # Offer the available IP
        offer_message = f"DHCPOffer {available_ip} {tid} LeaseTime {lease_time} {mac_address}".encode()
        server_socket.sendto(offer_message, client_address)
        print(f"Sent DHCP Offer with IP: {available_ip} to {client_address} with TID: {tid} and MAC: {mac_address}")

    @staticmethod
    def _handle_request(server_socket, client_address, data, ip_pool, lease_time):
        parts = data.decode().split(" ")
        requested_ip = parts[2]  # Extract requested IP
        tid = parts[3]  # Extract TID
        mac_address = parts[4]  # Extract MAC address
        print(f"Received DHCP Request for IP: {requested_ip} with TID: {tid} and MAC address: {mac_address}")

        # Check if the requested IP is valid and not currently leased
        if requested_ip not in ip_pool:
            nak_message = f"DHCP Nak Invalid IP {tid}".encode()
            server_socket.sendto(nak_message, client_address)
            print(f"Sent DHCP Nak to {client_address}: Invalid IP requested with TID: {tid}")
            return

        # Check if the IP is leased and if the renewal is valid
        lease_entry = Server.lease_table.get(tid)
        if lease_entry:
            leased_ip, lease_time_left, _ = lease_entry
            if leased_ip == requested_ip:
                # Renew the lease (extend the lease time)
                Server.lease_table[tid] = (requested_ip, lease_time, mac_address)
                ack_message = f"DHCP Acknowledge {requested_ip} {tid} LeaseTime {lease_time} {mac_address}".encode()
                server_socket.sendto(ack_message, client_address)
                print(f"Sent DHCP Acknowledge for IP: {requested_ip} to {client_address} with TID: {tid} and MAC: {mac_address}")
                return
            else:
                nak_message = f"DHCP Nak IP Mismatch {tid}".encode()
                server_socket.sendto(nak_message, client_address)
                print(f"Sent DHCP Nak to {client_address}: IP mismatch with TID: {tid}")
                return

        # If it's a new lease request
        if any(entry[0] == requested_ip for entry in Server.lease_table.values()):
            nak_message = f"DHCP Nak IP Already Leased {tid}".encode()
            server_socket.sendto(nak_message, client_address)
            print(f"Sent DHCP Nak to {client_address}: IP already leased with TID: {tid}")
            return

        # Acknowledge the lease
        Server.lease_table[tid] = (requested_ip, lease_time, mac_address)
        ack_message = f"DHCP Acknowledge {requested_ip} {tid} LeaseTime {lease_time} {mac_address}".encode()
        server_socket.sendto(ack_message, client_address)
        print(f"Sent DHCP Acknowledge for IP: {requested_ip} to {client_address} with TID: {tid} and MAC: {mac_address}")

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
        # Create a UDP socket
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        ipv4_address = get_valid_ipv4()
        server_address = (ipv4_address, 67)  # Listen on all network interfaces, port 67
        server_socket.bind(server_address)

        print("DHCP Server is running and listening on port 67...")

        # Simple IP pool (for demonstration purposes)
        ip_pool = ["192.168.1." + str(i) for i in range(100, 103)]
        lease_time = 10  # Lease time in seconds
        
        lease_thread = threading.Thread(target=Server._decrement_lease_times)
        lease_thread.daemon = True 
        lease_thread.start()

        while True:
            # Receive a message from the client
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
print(f"Current Lease Table: {Server.lease_table}")
print('>' * 40)