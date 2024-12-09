import socket
import random
import time

# Define a lease management system
lease_table = {}  # {tid: (assigned_ip, lease_expiry_time)}

def handle_discover(server_socket, client_address, ip_pool, lease_time, tid):
    print(f"Received DHCP Discover message with TID: {tid}")

    # Find the first available IP
    available_ip = None
    for ip in ip_pool:
        if ip not in [entry[0] for entry in lease_table.values()]:
            available_ip = ip
            break

    if available_ip is None:
        # If no IPs are available, send a DHCP Nak
        nak_message = f"DHCP Nak No Available IPs {tid}".encode()
        server_socket.sendto(nak_message, client_address)
        print(f"Sent DHCP Nak to {client_address}: No available IPs with TID: {tid}")
        return

    # Offer the available IP
    offer_message = f"DHCPOffer {available_ip} {tid} LeaseTime {lease_time}".encode()
    server_socket.sendto(offer_message, client_address)
    print(f"Sent DHCP Offer with IP: {available_ip} to {client_address} with TID: {tid}")


def handle_request(server_socket, client_address, data, ip_pool, lease_time):
    parts = data.decode().split(" ")
    requested_ip = parts[2]  # Extract requested IP
    tid = parts[3]  # Extract TID
    print(f"Received DHCP Request for IP: {requested_ip} with TID: {tid}")

    # Check if the requested IP is valid and not currently leased
    if requested_ip not in ip_pool:
        nak_message = f"DHCP Nak Invalid IP {tid}".encode()
        server_socket.sendto(nak_message, client_address)
        print(f"Sent DHCP Nak to {client_address}: Invalid IP requested with TID: {tid}")
        return

    if any(entry[0] == requested_ip for entry in lease_table.values()):
        nak_message = f"DHCP Nak IP Already Leased {tid}".encode()
        server_socket.sendto(nak_message, client_address)
        print(f"Sent DHCP Nak to {client_address}: IP already leased with TID: {tid}")
        return

    # Acknowledge the lease
    current_time = time.time()
    lease_expiry_time = current_time + lease_time     #/3600 AFTER TESTING
    lease_table[tid] = (requested_ip, lease_expiry_time)

    ack_message = f"DHCP Acknowledge {requested_ip} {tid} LeaseTime {lease_time}".encode()
    server_socket.sendto(ack_message, client_address)
    print(f"Sent DHCP Acknowledge for IP: {requested_ip} to {client_address} with TID: {tid}")


def start_server():
    # Create a UDP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_address = ("0.0.0.0", 67)  # Listen on all network interfaces, port 67
    server_socket.bind(server_address)

    print("DHCP Server is running and listening on port 67...")

    # Simple IP pool (for demonstration purposes)
    ip_pool = ["192.168.1." + str(i) for i in range(100, 103)]
    lease_time = 3600  # 1 hour lease time

    while True:
        # Receive a message from the client
        data, client_address = server_socket.recvfrom(1024)
        parts = data.decode().split(" ")
        print(f"Received message from {client_address}: {data.decode()}")

        # Handling DHCP Discover message
        if parts[0] == "DHCP" and parts[1] == "Discover":
            tid = parts[2]
            handle_discover(server_socket, client_address, ip_pool, lease_time, tid)

        # Handling DHCP Request message
        elif parts[0] == "DHCP" and parts[1] == "Request":
            handle_request(server_socket, client_address, data, ip_pool, lease_time)

        # Print current lease table for debugging
        print(f"Current Lease Table: {lease_table}")
        print('>' * 40)


if __name__ == "__main__":
    start_server()
