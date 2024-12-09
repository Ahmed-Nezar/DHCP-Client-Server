import argparse
from dhcp.dhcp_client import Client
from dhcp.dhcp_server import Server


# Initialize the argument parser
parser = argparse.ArgumentParser(description="Run a DHCP server or client")
parser.add_argument('--server', action='store_true', help="Run the DHCP server")
parser.add_argument('--client', action='store_true', help="Run the DHCP client")

# Parse the arguments
args = parser.parse_args()

# Check which flag was passed and start the corresponding process
if args.server:
    Server.start_server()
elif args.client:
    Client.start_client()
else:
    print("You must specify either --server or --client")

