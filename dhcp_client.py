import socket

def start_client():
    # Create a UDP socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_address = ("127.0.0.1", 67)  # Server IP and port (localhost for testing)

    try:
        # Step 1: Send DHCP Discover message
        message = "DHCP Discover".encode()
        print(f"Sending message: {message.decode()}")
        client_socket.sendto(message, server_address)

        # Step 2: Wait for DHCP Offer from the server
        offer_message, _ = client_socket.recvfrom(1024)
        print(f"Received message: {offer_message.decode()}")
        
        # Step 3: Extract offered IP and send DHCP Request
        offered_ip = offer_message.decode().split(" ")[1]
        request_message = f"DHCPOffered {offered_ip}".encode()
        print(f"Sending DHCP Request for IP: {offered_ip}")
        client_socket.sendto(request_message, server_address)

        # Step 4: Wait for DHCP Acknowledge
        ack_message, _ = client_socket.recvfrom(1024)
        print(f"Received message: {ack_message.decode()}")

    finally:
        client_socket.close()

if __name__ == "__main__":
    start_client()
