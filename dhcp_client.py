import socket

def start_client():
    # Create a UDP socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_address = ("127.0.0.1", 67)  # Target server on localhost and port 67

    try:
        # Send a message to the server
        message = "DHCP Discover".encode()
        print(f"Sending message: {message.decode()}")
        client_socket.sendto(message, server_address)

        # Wait for a response from the server
        response, _ = client_socket.recvfrom(1024)
        print(f"Received response: {response.decode()}")

    finally:
        client_socket.close()

if __name__ == "__main__":
    start_client()
