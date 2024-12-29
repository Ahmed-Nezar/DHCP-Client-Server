import socket
import random
import time
from dhcp.utils import get_valid_ipv4, DHCPMessage
import signal

class DHCPClient:
    def __init__(self, options):
        self.options = options
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("0.0.0.0", 0))
        self.server_ip = get_valid_ipv4()
        self.tid = random.randint(1, 100000)

    def send_discover(self):
        print("Sending DHCP Discover...")
        discover_msg = DHCPMessage(1, tid=self.tid)
        for option, value in self.options.items():
            print(f"Setting option {option} to {value}")
            discover_msg.set_option(option, value)
        self.sock.sendto(discover_msg.to_json().encode(), (self.server_ip, 67))

    def send_request(self, offered_ip):
        print(f"Sending DHCP Request for IP: {offered_ip}")
        request_msg = DHCPMessage(3, tid=self.tid)
        for option, value in self.options.items():
            request_msg.set_option(option, value)
        self.sock.sendto(request_msg.to_json().encode(), (self.server_ip, 67))

    def release_ip(self, signum, frame):
        print("Releasing IP...")
        release_msg = DHCPMessage(7, tid=self.tid)
        for option, value in self.options.items():
            release_msg.set_option(option, value)
        self.sock.sendto(release_msg.to_json().encode(), (self.server_ip, 67))
        self.sock.close()
        exit(0)

    def _recieve_offer(self):
        data, addr = self.sock.recvfrom(1024)
        message = DHCPMessage.from_json(data.decode())
        print(f"Received message: {message}")
        if message.message_type == 2:
            offered_ip = message.get_option(50)
            print(f"Received offer: {offered_ip}")
            self.send_request(offered_ip)
        else:
            print("Unexpected message received. Terminating connection.")


    def _recieve_ack(self):
        data, addr = self.sock.recvfrom(1024)
        message = DHCPMessage.from_json(data.decode())
        print(f"Received message: {message}")
        if message.message_type == 5:
            print("Received DHCP ACK. Lease obtained.")
            self.sock.close()
            exit(0)
            
        elif message.message_type == 6:
            print("Received DHCP NAK. No IP address available. Terminating connection.")
            self.sock.close()
            exit(1)

    def listen(self):        
        try:
            self.send_discover()
            self._recieve_offer()
            self._recieve_ack()


        except Exception as e:
            print(f"Error: {e}")



class Client:
    
    lease_time = 10  # Lease time in seconds
    lease_timer = None  # Timer to track remaining lease time
    
    # Threshold for lease time to decline the offer
    @staticmethod
    def _select_ramdom_decline_threshold():
        predefined_decline_threshold = 3600
        return 5 if random.choice([True, True, True, False]) else predefined_decline_threshold
    
    decline_threshold = _select_ramdom_decline_threshold()
    
    @staticmethod
    def _send_dhcp_discover(client_socket, server_address, TID, mac_address):
        message = f"DHCP Discover {TID} {mac_address}".encode()
        print(f"Sending message: {message.decode()}")
        client_socket.sendto(message, server_address)

    @staticmethod
    def _receive_dhcp_offer(client_socket):
        response, _ = client_socket.recvfrom(1024)
        response_message = response.decode()
        
        print(f"Received message: {response_message}")

        if response_message.startswith("DHCP Nak"):
            print("Received DHCP Nak: No IP address available. Terminating connection.")
            return None, None, None  # Indicates failure to obtain an IP
        elif response_message.startswith("DHCPOffer"):
            parts = response_message.split(" ")
            if len(parts) < 4:  # Check if the expected format is correct
                print("Invalid DHCPOffer message format.")
                return None, None, None
            offered_ip = parts[1]
            Client.lease_time = int(parts[4])
            return offered_ip, parts[2], Client.lease_time  # Offered IP, TID, Lease Time
        else:
            print("Unexpected message received. Terminating connection.")
            return None, None, None

    @staticmethod
    def _send_dhcp_request(client_socket, server_address, offered_ip, TID, mac_address, lease_time):
        request_message = f"DHCP Request {offered_ip} {TID} {mac_address} {lease_time}".encode()
        print(f"Sending DHCP Request for IP: {offered_ip} with TID: {TID} with MAC: {mac_address} and Lease Time: {lease_time}")
        client_socket.sendto(request_message, server_address)

    @staticmethod
    def _send_dhcp_decline(client_socket, server_address, offered_ip, TID, mac_address):
        decline_message = f"DHCP Decline {offered_ip} {TID} {mac_address} {Client.decline_threshold}".encode()
        print(f"Sending DHCP Decline for IP: {offered_ip} with TID: {TID} with MAC: {mac_address}")
        client_socket.sendto(decline_message, server_address)

    @staticmethod
    def _receive_dhcp_ack(client_socket):
        ack_message, _ = client_socket.recvfrom(1024)
        print(f"Received message: {ack_message.decode()}")

    @staticmethod
    def _select_random_mac():
        mac = [0x00, 0x16, 0x3e,
               random.randint(0x00, 0x7f),
               random.randint(0x00, 0xff),
               random.randint(0x00, 0xff)]
        random_mac = ':'.join(map(lambda x: "%02x" % x, mac))
        predefined_mac = "18:05:03:30:11:03"
        return random_mac if random.choice([True, True, True, False]) else predefined_mac

    @staticmethod
    def _send_renewal_request(client_socket, server_address, offered_ip, TID, mac_address):
        print("Sending DHCP Renewal Request for IP: " + offered_ip)
        Client._send_dhcp_request(client_socket, server_address, offered_ip, TID, mac_address, Client.lease_time)
        
    @staticmethod
    def start_client():
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)  # Enable broadcast
        client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        client_socket.bind(("0.0.0.0", 0))  # Bind to 0.0.0.0 with a dynamic source port
        
        server_address = (get_valid_ipv4(), 67)  # DHCP server port and broadcast address

        try:
            TID = random.randint(1, 100000)  # Generate a random transaction ID
            mac_address = Client._select_random_mac()  # Generate or choose a MAC address
            Client._send_dhcp_discover(client_socket, server_address, TID, mac_address)
            offered_ip, response_TID, offered_lease_time = Client._receive_dhcp_offer(client_socket)

            if offered_ip is None or str(TID) != response_TID:
                print("Transaction ID mismatch or no IP address obtained. Exiting.")
                return

            # Decline the offer if the lease time is below the threshold
            if offered_lease_time < Client.decline_threshold:
                Client._send_dhcp_decline(client_socket, server_address, offered_ip, TID, mac_address)
                print(f"Lease time below threshold, declined the offer for IP: {offered_ip}")
                return

            # Proceed with DHCP Request if the lease time is acceptable
            Client._send_dhcp_request(client_socket, server_address, offered_ip, TID, mac_address, offered_lease_time)
            Client._receive_dhcp_ack(client_socket)
            def release_ip(signum, frame):
                print("Client terminated. Releasing IP...")
                release_message = f"DHCP Release {offered_ip} {TID} {mac_address}".encode()
                client_socket.sendto(release_message, server_address)
                client_socket.close()
                exit(0)

            # Register signal handler for termination
            signal.signal(signal.SIGINT, release_ip)
            signal.signal(signal.SIGTERM, release_ip)

            # Start the lease time countdown
            Client.lease_timer = Client.lease_time

            # Monitor lease time for renewal
            while Client.lease_timer > 0:
                time.sleep(1)
                Client.lease_timer -= 1

                # Send renewal request when lease time is halved
                if Client.lease_timer == Client.lease_time // 2:
                    print("Lease time halved, sending renewal request...")
                    Client._send_renewal_request(client_socket, server_address, offered_ip, TID, mac_address)
                    Client._receive_dhcp_ack(client_socket)
                    Client.lease_timer = Client.lease_time  # Reset lease timer after renewal

            print("Lease expired. Releasing IP...")
            release_message = f"DHCP Release {offered_ip} {TID} {mac_address}".encode()
            client_socket.sendto(release_message, server_address)
            
        finally:
            client_socket.close()
