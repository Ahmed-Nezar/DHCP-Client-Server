import socket
import random

def handle_discover(server_socket, client_address, ip_pool, lease_time):
    print("Received DHCP Discover message.")
    
    # Offer an IP address
    offered_ip = random.choice(ip_pool)
    offer_message = f"DHCPOffer {offered_ip} LeaseTime {lease_time}".encode()
    server_socket.sendto(offer_message, client_address)
    print(f"Sent DHCP Offer with IP: {offered_ip}")

def handle_request(server_socket, client_address, data):
    requested_ip = data.decode().split(" ")[1]  # Extract requested IP
    print(f"Received DHCP Request for IP: {requested_ip}")
    
    # Acknowledge the client's request
    ack_message = f"DHCP Acknowledge {requested_ip}".encode()
    server_socket.sendto(ack_message, client_address)
    print(f"Sent DHCP Acknowledge for IP: {requested_ip}")

def start_server():
    # Create a UDP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_address = ("0.0.0.0", 67)  # Listen on all network interfaces, port 67
    server_socket.bind(server_address)

    print("DHCP Server is running and listening on port 67...")

    # Simple IP pool (for demonstration purposes)
    ip_pool = ["192.168.1." + str(i) for i in range(100, 200)]
    lease_time = 3600  # 1 hour lease time 
    # DONT FORGET TO RE INCREASE THE LEASE TIME TO 3600 (TESTING PURPOSE)

    while True:
        # Receive a message from the client
        data, client_address = server_socket.recvfrom(1024)
        print(f"Received message from {client_address}: {data.decode()}")

        # Handling DHCP Discover message
        if data.decode() == "DHCP Discover":
            handle_discover(server_socket, client_address, ip_pool, lease_time)

        # Handling DHCP Request message
        elif "DHCPOffered" in data.decode():
            handle_request(server_socket, client_address, data)
        
if __name__ == "__main__":
    start_server()
