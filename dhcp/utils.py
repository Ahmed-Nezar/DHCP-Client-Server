import socket
import json

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
    

class DHCPMessage:
    """
    Class to represent a DHCP message with type and options.
    """

    MESSAGE_TYPES = {
        1: "DHCPDISCOVER",
        2: "DHCPOFFER",
        3: "DHCPREQUEST",
        4: "DHCPDECLINE",
        5: "DHCPACK",
        6: "DHCPNAK",
        7: "DHCPRELEASE",
        8: "DHCPINFORM",
    }

    DHCP_OPTIONS = {
        1: "Subnet Mask",
        3: "Router",
        6: "Domain Name Server",
        12: "Host Name",
        15: "Domain Name",
        28: "Broadcast Address",
        50: "Requested IP Address",
        51: "IP Address Lease Time",
        53: "DHCP Message Type",
        54: "DHCP Server Identifier",
        55: "Parameter Request List",
        56: "Message (Error Message)",
        58: "Renewal Time",
        59: "Rebinding Time",
        60: "Vendor Class Identifier",
        61: "Client Identifier",
        255: "End",
    }

    def __init__(self, message_type, options=None, tid=None):
        """
        Initialize a DHCP message.

        :param message_type: DHCP message type (integer, e.g., 1 for DHCPDISCOVER).
        :param options: Dictionary of DHCP options (default: None).
        :param tid: Transaction ID for the DHCP message.
        """
        if message_type not in self.MESSAGE_TYPES:
            raise ValueError(f"Invalid DHCP message type: {message_type}")

        self.tid = tid
        if not isinstance(options, dict):
            options = {}
        self.message_type = message_type
        self.options = {int(k): v for k, v in options.items()}

    def set_option(self, option_number, option_value):
        """
        Set an option for the DHCP message.

        :param option_number: DHCP option number.
        :param option_value: Value for the option.
        """
        self.options[option_number] = option_value

    def get_option(self, option_number):
        """
        Get the value of a specific DHCP option.

        :param option_number: DHCP option number.
        :return: Value of the option, or None if not set.
        """
        if option_number not in self.options:
            print(f"Option {option_number} not found in options: {self.options}")
            return None
        
        return self.options.get(option_number)

    def to_dict(self):
        """
        Convert the DHCP message to a dictionary.

        :return: Dictionary representation of the DHCP message.
        """
        return {
            "message_type": self.MESSAGE_TYPES[self.message_type],
            "tid": self.tid,
            "options": self.options,
        }
    
    def to_json(self):
        """
        Convert the DHCP message to a JSON string.

        :return: JSON representation of the DHCP message.
        """
        return json.dumps(self.to_dict())

    @staticmethod
    def from_json(data):
        """
        Create a DHCPMessage object from a JSON string.
        """
        obj = json.loads(data)
        message_type = list(DHCPMessage.MESSAGE_TYPES.keys())[list(DHCPMessage.MESSAGE_TYPES.values()).index(obj["message_type"])]
        tid = obj.get("tid")
        return DHCPMessage(message_type, obj["options"], tid)

    def __repr__(self):
        return f"DHCPMessage({self.MESSAGE_TYPES[self.message_type]}, options={self.options}),   tid={self.tid})"