import socket
import random

class Client:
    
    @staticmethod
    def _send_dhcp_discover(client_socket, server_address, TID):
        message = f"DHCP Discover {TID}".encode()
        print(f"Sending message: {message.decode()}")
        client_socket.sendto(message, server_address)
    @staticmethod
    def _receive_dhcp_offer(client_socket):
        response, _ = client_socket.recvfrom(1024)
        response_message = response.decode()
        print(f"Received message: {response_message}")

        if response_message.startswith("DHCP Nak"):
            print("Received DHCP Nak: No IP address available. Terminating connection.")
            return None, None  # Indicates failure to obtain an IP
        elif response_message.startswith("DHCPOffer"):
            parts = response_message.split(" ")
            return parts[1], parts[2]  # Extract the offered IP and TID
        else:
            print("Unexpected message received. Terminating connection.")
            return None, None
    @staticmethod
    def _send_dhcp_request(client_socket, server_address, offered_ip, TID):
        request_message = f"DHCP Request {offered_ip} {TID}".encode()
        print(f"Sending DHCP Request for IP: {offered_ip} with TID: {TID}")
        client_socket.sendto(request_message, server_address)

    @staticmethod
    def _receive_dhcp_ack(client_socket):
        ack_message, _ = client_socket.recvfrom(1024)
        print(f"Received message: {ack_message.decode()}")
    
    @staticmethod
    def start_client():
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server_address = ("127.0.0.1", 67)  # Server IP and port (localhost for testing)

        try:
            TID = random.randint(1, 100000)  # Generate a random transaction ID
            Client._send_dhcp_discover(client_socket, server_address, TID)
            offered_ip, response_TID = Client._receive_dhcp_offer(client_socket)

            if offered_ip is None or str(TID) != response_TID:
                print("Transaction ID mismatch or no IP address obtained. Exiting.")
                return
            
            Client._send_dhcp_request(client_socket, server_address, offered_ip, TID)
            Client._receive_dhcp_ack(client_socket)
        finally:
            client_socket.close()