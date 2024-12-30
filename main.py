import argparse
from dhcp.dhcp_server import Server

# Initialize the argument parser
parser = argparse.ArgumentParser(description="Run a DHCP server or client")
parser.add_argument('--server', action='store_true', help="Run the DHCP server", default=None)
parser.add_argument('--client', action='store_true', help="Run the DHCP client", default=None)
parser.add_argument('--lease-time', action='store', help="Enable debug mode", default=None)
parser.add_argument('--NAK', action='store_true', help="Enable debug mode", default=None)
parser.add_argument('--INFORM', action='store_true', help="Run the DHCP client in INFORM mode", default=None)

# Parse the arguments
args = parser.parse_args()

def collect_user_input():
    client_id = input("Enter Client Identifier (MAC Address, e.g., 00:11:22:33:44:55): ")
    requested_ip = input("Enter Requested IP Address (or leave blank): ")
    lease_time = input("Enter Lease Time in seconds (or leave blank for default): ")
    escape_discover = input("Enter 'y' to escape Discover message: ")

    config = {
        "client_mac": client_id,
        "requested_ip": requested_ip,
        "lease_time": int(lease_time) if lease_time else "",
        "escape_discover": 1 if escape_discover == 'y' else 0,
        "inform": 1 if args.INFORM else 0
    }

    return config

# Check which flag was passed and start the corresponding process
if args.server:
    Server.start_dhcp_server(args)
elif args.client:
    from client.virtual_client import DHCP_Client
    client_options = collect_user_input()
    client = DHCP_Client().start(client_options)
elif args.INFORM:
    from client.virtual_client import DHCP_Client
    client_options = collect_user_input()
    client = DHCP_Client().start(client_options)
else:
    print("You must specify either --server or --client or --INFORM")
