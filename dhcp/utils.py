import socket

@staticmethod
def get_valid_ipv4():
    try:
        # Create a socket and connect to a public server to get the active interface
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))  # Google's public DNS
            ip_address = s.getsockname()[0]  # Get the IP address
            # Validate that the IP is not a loopback or autoconfiguration address
            if ip_address.startswith("169.") or ip_address.startswith("127."):
                return "No valid IPv4 address found."
            return ip_address
    except Exception as e:
        return f"Error retrieving IP: {e}"