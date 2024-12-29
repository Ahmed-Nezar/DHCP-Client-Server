import argparse
from dhcp.dhcp_server import Server


# Initialize the argument parser
parser = argparse.ArgumentParser(description="Run a DHCP server or client")
parser.add_argument('--server', action='store_true', help="Run the DHCP server", default=None)
parser.add_argument('--client', action='store_true', help="Run the DHCP client", default=None)
parser.add_argument('--lease-time', action='store', help="Enable debug mode", default=None)
parser.add_argument('--NAK', action='store_true', help="Enable debug mode", default=None)

# Parse the arguments
args = parser.parse_args()

def collect_user_input():
    client_id = input("Enter Client Identifier (MAC Address, e.g., 00:11:22:33:44:55): ")
    requested_ip = input("Enter Requested IP Address (or leave blank): ")
    hostname = input("Enter Hostname (or leave blank): ")
    vendor_class = input("Enter Vendor Class Identifier (or leave blank): ")
    lease_time = input("Enter Lease Time in seconds (or leave blank for default): ")
    parameter_request_list = input("Enter Parameter Request List (comma-separated, e.g., 1,3,6,51): ")

    if not client_id:
        client_id = "00:11:22:33:44:55"
    if not lease_time:
        lease_time = 10
    if not parameter_request_list:
        parameter_request_list = "1,3,6,51"

    options = {
        61: client_id,
    }
    if requested_ip:
        options[50] = requested_ip
    if hostname:
        options[12] = hostname
    if vendor_class:
        options[60] = vendor_class
    if lease_time:
        options[51] = int(lease_time)
    if parameter_request_list:
        options[55] = list(map(int, parameter_request_list.split(',')))

    print(f"Options: {options}")

    return options


# Check which flag was passed and start the corresponding process
if args.server:
    Server.start_dhcp_server(args)
elif args.client:
    from client.virtual_client import DHCP_Client
    client_options = collect_user_input()
    client = DHCP_Client(options=client_options)
    client.listen()
else:
    print("You must specify either --server or --client or --LAN")

