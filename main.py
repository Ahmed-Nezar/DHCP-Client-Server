from dhcp.dhcp_server import Server
from client.virtual_client import DHCP_Client
from utils.utils import parse_arguments, collect_user_input
from multiprocessing import Queue


args = parse_arguments()

if args.server:
    Server.start_dhcp_server(args, Queue())
elif args.client:
    client_options = collect_user_input(args)
    client = DHCP_Client().start(client_options)
elif args.INFORM:
    client_options = collect_user_input(args, inform=True)
    client = DHCP_Client().start(client_options)
else:
    raise ValueError("You must specify either --server or --client or --INFORM")
