import argparse
from dhcp.dhcp_client import Client
from dhcp.dhcp_server import Server
from dhcp.LAN_dhcp_server import LAN_Server


# Initialize the argument parser
parser = argparse.ArgumentParser(description="Run a DHCP server or client")
parser.add_argument('--server', action='store_true', help="Run the DHCP server")
parser.add_argument('--client', action='store_true', help="Run the DHCP client")
parser.add_argument('--LAN', action='store_true', help="Run the DHCP LAN server")

# Parse the arguments
args = parser.parse_args()

# Check which flag was passed and start the corresponding process
if args.server:
    Server.start_server()
elif args.client:
    Client.start_client()
elif args.LAN:
    LAN_Server.start_dhcp_server()
else:
    print("You must specify either --server or --client or --LAN")

