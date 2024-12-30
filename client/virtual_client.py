import socket
import struct
import random
import time
import signal

class DHCP_Client:
    CLIENT_PORT = 68
    SERVER_PORT = 67
    BROADCAST_IP = "255.255.255.255"
    LEASE_TIMER = 0

    @staticmethod
    def generate_transaction_id():
        """Generate a random transaction ID."""
        return random.randint(0, 0xFFFFFFFF)

    @staticmethod
    def generate_mac_address():
        """Generate a random MAC address."""
        return ':'.join([f"{random.randint(0, 255):02x}" for _ in range(6)])

    @staticmethod
    def create_dhcp_discover(transaction_id, mac_address, requested_lease_time):
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
        if requested_lease_time:
            options += b'\x33\x04' + struct.pack('!I', int(requested_lease_time))  # Requested Lease Time
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
    def create_dhcp_release(transaction_id, mac_address, leased_ip):
        """Create a DHCP Release packet."""
        chaddr = bytes.fromhex(mac_address.replace(':', '')) + b'\x00' * 10

        # DHCP Release packet
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

        # DHCP options (Message Type = Release)
        options = b'\x35\x01\x07'  # DHCP Message Type: Release
        options += b'\x32\x04' + socket.inet_aton(leased_ip)  # Leased IP Address
        options += b'\xff'  # End of options

        return packet + options
    
    @staticmethod
    def find_lease_time(data):
        options = data[240:]  # Options start at byte 240

        lease_time = None

        i = 0
        while i < len(options):
            option_type = options[i]
            if option_type == 255:
                break
            length = options[i + 1]
            if option_type == 51:
                lease_time = struct.unpack("!I", options[i + 2:i + 2 + length])[0]
            i += 2 + length

        return lease_time

    @staticmethod
    def start(config: dict):
        """Start the DHCP client."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.bind(("0.0.0.0", DHCP_Client.CLIENT_PORT))

        transaction_id = DHCP_Client.generate_transaction_id()
        mac_address = config.get("client_id") or DHCP_Client.generate_mac_address()
        requested_lease_time = config.get("lease_time")

        # Send DHCP Discover
        discover_packet = DHCP_Client.create_dhcp_discover(transaction_id, mac_address, requested_lease_time)
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
                    offered_ip = socket.inet_ntoa(data[16:20])
                    print(f"Offered IP: {offered_ip}")
                    offered_lease_time = DHCP_Client.find_lease_time(data)

                    # Simulate checking the offered IP (replace with actual validation logic if needed)
                    if config['requested_ip'] and offered_ip != config['requested_ip']:
                        print(f"Offered IP {offered_ip} does not match requested IP {config['requested_ip']}")
                        decline_packet = DHCP_Client.create_dhcp_decline(transaction_id, mac_address,declined_ip=offered_ip)
                        sock.sendto(decline_packet, (DHCP_Client.BROADCAST_IP, DHCP_Client.SERVER_PORT))
                        print("Sent DHCP Decline for IP", offered_ip)
                        return
                    
                    if config['lease_time'] and offered_lease_time < config['lease_time']:
                        decline_packet = DHCP_Client.create_dhcp_decline(transaction_id, mac_address, declined_lease_time=offered_lease_time)
                        sock.sendto(decline_packet, (DHCP_Client.BROADCAST_IP, DHCP_Client.SERVER_PORT))
                        print("Sent DHCP Decline for lease time", offered_lease_time)
                        return

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

        def release_ip(signum, frame):
            print("Client terminated. Releasing IP...")
            release_message = DHCP_Client.create_dhcp_release(transaction_id, mac_address, leased_ip)
            sock.sendto(release_message, (DHCP_Client.BROADCAST_IP, DHCP_Client.SERVER_PORT))
            print("Sent DHCP Release")
            sock.close()
            exit(0)

        # Register signal handler for termination
        signal.signal(signal.SIGINT, release_ip)
        signal.signal(signal.SIGTERM, release_ip)
        # Simulate DHCP client behavior
        DHCP_Client.LEASE_TIMER = offered_lease_time
        print(f"Lease time: {DHCP_Client.LEASE_TIMER} seconds")
        while DHCP_Client.LEASE_TIMER > 0:
            DHCP_Client.LEASE_TIMER -= 1
            time.sleep(1)

            if DHCP_Client.LEASE_TIMER == offered_lease_time // 2:
                print("Renewing lease...")
                request_packet = DHCP_Client.create_dhcp_request(transaction_id, mac_address, leased_ip, offered_lease_time)
                sock.sendto(request_packet, (DHCP_Client.BROADCAST_IP, DHCP_Client.SERVER_PORT))
                print("Sent DHCP Renewal Request")

                data, address = sock.recvfrom(1024)
                if data[236:240] == b'\x63\x82\x53\x63':
                    DHCP_Client.LEASE_TIMER = offered_lease_time
                    print(f"Received DHCP Ack from {address}")


        sock.close()
