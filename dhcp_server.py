import socket

def start_server():
    # Create a UDP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_address = ("0.0.0.0", 67)  # Listen on all network interfaces on port 67
    server_socket.bind(server_address)

    print("DHCP Server is running and listening on port 67...")

    while True:
        # Receive data from a client
        data, client_address = server_socket.recvfrom(1024)  # Buffer size 1024 bytes
        print(f"Received message from {client_address}: {data.decode()}")

        # Respond to the client
        response = "ACK: Message received".encode()
        server_socket.sendto(response, client_address)

if __name__ == "__main__":
    start_server()
