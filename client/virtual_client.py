import socket
import struct
import random

class DHCP_Client:
    CLIENT_PORT = 68
    SERVER_PORT = 67
    BROADCAST_IP = "255.255.255.255"

    @staticmethod
    def generate_transaction_id():
        """Generate a random transaction ID."""
        return random.randint(0, 0xFFFFFFFF)

    @staticmethod
    def generate_mac_address():
        """Generate a random MAC address."""
        return ':'.join([f"{random.randint(0, 255):02x}" for _ in range(6)])

    @staticmethod
    def create_dhcp_discover(transaction_id, mac_address):
        """Create a DHCP Discover packet."""
        chaddr = bytes.fromhex(mac_address.replace(':', '')) + b'\x00' * 10

        # DHCP Discover packet
        packet = struct.pack(
            '!BBBBIHH4s4s4s4s16s192sI',
            1,  # op: Boot Request
            1,  # htype: Ethernet
            6,  # hlen: MAC length
            0,  # hops
            transaction_id,  # Transaction ID
            0,  # Seconds elapsed
            0x8000,  # Flags: Broadcast
            b'\x00\x00\x00\x00',  # Client IP
            b'\x00\x00\x00\x00',  # Your IP
            b'\x00\x00\x00\x00',  # Server IP
            b'\x00\x00\x00\x00',  # Gateway IP
            chaddr,  # Client hardware address (MAC)
            b'\x00' * 192,  # Padding
            0x63825363,  # Magic cookie
        )

        # DHCP options (Message Type = Discover)
        options = b'\x35\x01\x01'  # DHCP Message Type: Discover
        options += b'\x37\x03\x01\x03\x06'  # Parameter Request List: Subnet Mask, Router, DNS Server
        options += b'\xff'  # End of options

        return packet + options

    @staticmethod
    def create_dhcp_request(transaction_id, mac_address, offered_ip, requested_lease_time=None):
        """Create a DHCP Request packet."""
        chaddr = bytes.fromhex(mac_address.replace(':', '')) + b'\x00' * 10

        # DHCP Request packet
        packet = struct.pack(
            '!BBBBIHH4s4s4s4s16s192sI',
            1,  # op: Boot Request
            1,  # htype: Ethernet
            6,  # hlen: MAC length
            0,  # hops
            transaction_id,  # Transaction ID
            0,  # Seconds elapsed
            0x8000,  # Flags: Broadcast
            b'\x00\x00\x00\x00',  # Client IP
            b'\x00\x00\x00\x00',  # Your IP
            b'\x00\x00\x00\x00',  # Server IP
            b'\x00\x00\x00\x00',  # Gateway IP
            chaddr,  # Client hardware address (MAC)
            b'\x00' * 192,  # Padding
            0x63825363,  # Magic cookie
        )

        # DHCP options (Message Type = Request)
        options = b'\x35\x01\x03'  # DHCP Message Type: Request
        options += b'\x32\x04' + socket.inet_aton(offered_ip)  # Requested IP Address
        options += b'\x36\x04' + socket.inet_aton(DHCP_Client.BROADCAST_IP)  # DHCP Server Identifier

        if requested_lease_time:
            options += b'\x33\x04' + struct.pack('!I', int(requested_lease_time))  # Requested Lease Time

        options += b'\xff'  # End of options

        return packet + options

    @staticmethod
    def create_dhcp_decline(transaction_id, mac_address, declined_ip=None, declined_lease_time=None):
        """Create a DHCP Decline packet."""
        chaddr = bytes.fromhex(mac_address.replace(':', '')) + b'\x00' * 10

        # DHCP Decline packet
        packet = struct.pack(
            '!BBBBIHH4s4s4s4s16s192sI',
            1,  # op: Boot Request
            1,  # htype: Ethernet
            6,  # hlen: MAC length
            0,  # hops
            transaction_id,  # Transaction ID
            0,  # Seconds elapsed
            0x8000,  # Flags: Broadcast
            b'\x00\x00\x00\x00',  # Client IP
            b'\x00\x00\x00\x00',  # Your IP
            b'\x00\x00\x00\x00',  # Server IP
            b'\x00\x00\x00\x00',  # Gateway IP
            chaddr,  # Client hardware address (MAC)
            b'\x00' * 192,  # Padding
            0x63825363,  # Magic cookie
        )

        # DHCP options (Message Type = Decline)
        options = b'\x35\x01\x04'  # DHCP Message Type: Decline
        if declined_ip:
            options += b'\x32\x04' + socket.inet_aton(declined_ip)  # Declined IP Address
        if declined_lease_time:
            options += b'\x33\x04' + struct.pack('!I', int(declined_lease_time))
        options += b'\xff'  # End of options

        return packet + options

    @staticmethod
    def start(config: dict):
        """Start the DHCP client."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.bind(("0.0.0.0", DHCP_Client.CLIENT_PORT))

        transaction_id = DHCP_Client.generate_transaction_id()
        mac_address = config['client_id'] if config['client_id'] else DHCP_Client.generate_mac_address()

        # Send DHCP Discover
        discover_packet = DHCP_Client.create_dhcp_discover(transaction_id, mac_address)
        sock.sendto(discover_packet, (DHCP_Client.BROADCAST_IP, DHCP_Client.SERVER_PORT))
        print("Sent DHCP Discover")

        # Receive DHCP Offer
        while True:
            data, address = sock.recvfrom(1024)
            if data[236:240] == b'\x63\x82\x53\x63':  # Check for Magic Cookie
                if b'\x35\x01\x06' in data: # DHCP Message Type: Nak
                    print(f"Received DHCP Nak from {address}")
                    print("Lease request denied.")
                    sock.close()
                    return
                elif b'\x35\x01\x02' in data:  # DHCP Message Type: Offer
                    print(f"Received DHCP Offer from {address}")
                    # print(f"Received message: {data}")
                    offered_ip = socket.inet_ntoa(data[16:20])
                    print(f"Offered IP: {offered_ip}")
                    offered_lease_time = struct.unpack('!I', data[244:248])[0]

                    # Simulate checking the offered IP (replace with actual validation logic if needed)
                    if config['requested_ip'] and offered_ip != config['requested_ip']:
                        print(f"Offered IP {offered_ip} does not match requested IP {config['requested_ip']}")
                        decline_packet = DHCP_Client.create_dhcp_decline(transaction_id, mac_address,declined_ip=offered_ip)
                        sock.sendto(decline_packet, (DHCP_Client.BROADCAST_IP, DHCP_Client.SERVER_PORT))
                        print("Sent DHCP Decline for IP", offered_ip)
                        return
                    
                    if config['lease_time'] and offered_lease_time < config['lease_time']:
                        print("Offered lease time is less than requested lease time do you want to continue? (y/n)")
                        choice = input()
                        if choice.lower() == 'n':
                            decline_packet = DHCP_Client.create_dhcp_decline(transaction_id, mac_address, declined_lease_time=offered_lease_time)
                            sock.sendto(decline_packet, (DHCP_Client.BROADCAST_IP, DHCP_Client.SERVER_PORT))
                            print("Sent DHCP Decline for lease time", offered_lease_time)
                            return
                        else:
                            print("Continuing with the offered lease time")
                            config['lease_time'] = offered_lease_time

                    break
            
        request_packet = DHCP_Client.create_dhcp_request(transaction_id, mac_address, offered_ip, config['lease_time'])
        sock.sendto(request_packet, (DHCP_Client.BROADCAST_IP, DHCP_Client.SERVER_PORT))
        print("Sent DHCP Request")

        # Receive DHCP Ack or Nak
        while True:
            data, address = sock.recvfrom(1024)
            if data[236:240] == b'\x63\x82\x53\x63':  # Check for Magic Cookie
                if b'\x35\x01\x05' in data:  # DHCP Message Type: Ack
                    print(f"Received DHCP Ack from {address}")
                    leased_ip = socket.inet_ntoa(data[16:20])
                    print(f"Leased IP: {leased_ip}")
                    break
                if b'\x35\x01\x06' in data: # DHCP Message Type: Nak
                    print(f"Received DHCP Nak from {address}")
                    print("Lease request denied.")
                    break 

        sock.close()
