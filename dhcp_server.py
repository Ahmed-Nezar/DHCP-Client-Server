import socket
import random
import time

# Define a lease management system
lease_table = {}  # {client_address: (assigned_ip, lease_expiry_time)}

def handle_discover(server_socket, client_address, ip_pool, lease_time):
    print("Received DHCP Discover message.")

    # Find the first available IP
    available_ip = None
    for ip in ip_pool:
        if ip not in [entry[0] for entry in lease_table.values()]:
            available_ip = ip
            break

    if available_ip is None:
        # If no IPs are available, send a DHCP Nak
        nak_message = "DHCP Nak No Available IPs".encode()
        server_socket.sendto(nak_message, client_address)
        print(f"Sent DHCP Nak to {client_address}: No available IPs")
        return

    # Offer the available IP
    offer_message = f"DHCPOffer {available_ip} LeaseTime {lease_time}".encode()
    server_socket.sendto(offer_message, client_address)
    print(f"Sent DHCP Offer with IP: {available_ip} to {client_address}")


def handle_request(server_socket, client_address, data, ip_pool, lease_time):
    requested_ip = data.decode().split(" ")[1]  # Extract requested IP
    print(f"Received DHCP Request for IP: {requested_ip}")

    # Check if the requested IP is valid and not currently leased
    if requested_ip not in ip_pool:
        nak_message = "DHCP Nak Invalid IP".encode()
        server_socket.sendto(nak_message, client_address)
        print(f"Sent DHCP Nak to {client_address}: Invalid IP requested")
        return

    if any(entry[0] == requested_ip for entry in lease_table.values()):
        nak_message = "DHCP Nak IP Already Leased".encode()
        server_socket.sendto(nak_message, client_address)
        print(f"Sent DHCP Nak to {client_address}: IP already leased")
        return

    # Acknowledge the lease
    current_time = time.time()
    lease_expiry_time = current_time + lease_time
    lease_table[client_address] = (requested_ip, lease_expiry_time)

    ack_message = f"DHCP Acknowledge {requested_ip} LeaseTime {lease_time}".encode()
    server_socket.sendto(ack_message, client_address)
    print(f"Sent DHCP Acknowledge for IP: {requested_ip} to {client_address}")


def start_server():
    # Create a UDP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_address = ("0.0.0.0", 67)  # Listen on all network interfaces, port 67
    server_socket.bind(server_address)

    print("DHCP Server is running and listening on port 67...")

    # Simple IP pool (for demonstration purposes)
    ip_pool = ["192.168.1." + str(i) for i in range(100, 102)]
    lease_time = 3600  # 1 hour lease time

    while True:
        # Receive a message from the client
        data, client_address = server_socket.recvfrom(1024)
        print(f"Received message from {client_address}: {data.decode()}")

        # Handling DHCP Discover message
        if data.decode() == "DHCP Discover":
            handle_discover(server_socket, client_address, ip_pool, lease_time)

        # Handling DHCP Request message
        elif "DHCPOffered" in data.decode():
            handle_request(server_socket, client_address, data, ip_pool, lease_time)

        # Print current lease table for debugging
        print(f"Current Lease Table: {lease_table}")
        print('>' * 40)


if __name__ == "__main__":
    start_server()
