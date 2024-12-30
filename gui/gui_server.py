import customtkinter as ctk
from tkinter import ttk
import threading
import argparse
import logging
from dhcp.dhcp_server import Server
from client.virtual_client import DHCP_Client

# Custom logging handler to redirect logs to the GUI
class TextHandler(logging.Handler):
    def __init__(self, text_widget):
        super().__init__()
        self.text_widget = text_widget

    def emit(self, record):
        log_message = self.format(record)
        self.text_widget.configure(state="normal")
        self.text_widget.insert("end", log_message + "\n")
        self.text_widget.configure(state="disabled")
        self.text_widget.see("end")  # Auto-scroll to the end

class DHCPServerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("DHCP Server Manager")
        ctk.set_appearance_mode("dark")  # Set theme
        ctk.set_default_color_theme("blue")

        # Frame for controls
        self.controls_frame = ctk.CTkFrame(self.root)
        self.controls_frame.pack(pady=10)

        self.start_button = ctk.CTkButton(self.controls_frame, text="Start Server", command=self.start_server)
        self.start_button.pack(side="left", padx=5)

        self.stop_button = ctk.CTkButton(self.controls_frame, text="Stop Server", state="disabled", command=self.stop_server)
        self.stop_button.pack(side="left", padx=5)

        self.start_client_button = ctk.CTkButton(self.controls_frame, text="Start Client", command=self.start_client)
        self.start_client_button.pack(side="left", padx=5)

        # Frame for leases
        self.leases_frame = ctk.CTkFrame(self.root)
        self.leases_frame.pack(padx=10, pady=10, fill="both", expand=True)
        ctk.CTkLabel(self.leases_frame, text="Display").pack(anchor="w")

        # MACs
        self.mac_label = ctk.CTkLabel(self.leases_frame, text="MAC Address")
        self.mac_label.pack(anchor="w", padx=5)
        self.mac_text = ctk.CTkTextbox(self.leases_frame, height=5)
        self.mac_text.pack(fill="x", padx=5)

        # IPs
        self.ip_label = ctk.CTkLabel(self.leases_frame, text="IP Address")
        self.ip_label.pack(anchor="w", padx=5)
        self.ip_text = ctk.CTkTextbox(self.leases_frame, height=5)
        self.ip_text.pack(fill="x", padx=5)


        # Lease Times
        self.lease_label = ctk.CTkLabel(self.leases_frame, text="Lease Time")
        self.lease_label.pack(anchor="w", padx=5)
        self.lease_text = ctk.CTkTextbox(self.leases_frame, height=5)
        self.lease_text.pack(fill="x", padx=5)

        # Frame for logs
        self.logs_frame = ctk.CTkFrame(self.root)
        self.logs_frame.pack(padx=10, pady=10, fill="both", expand=True)
        ctk.CTkLabel(self.logs_frame, text="Server Logs").pack(anchor="w")

        self.logs_text = ctk.CTkTextbox(self.logs_frame, height=10, state="disabled")
        self.logs_text.pack(fill="both", expand=True)

        # Logging handler setup
        self.log_handler = TextHandler(self.logs_text)
        formatter = logging.Formatter('%(asctime)s - %(message)s')
        self.log_handler.setFormatter(formatter)
        logging.getLogger().addHandler(self.log_handler)
        logging.getLogger().setLevel(logging.INFO)

        self.server_thread = None
        self.server_running = False

    def start_server(self):
        """Start the server in a new thread."""
        self.server_thread = threading.Thread(target=self.run_server, daemon=True)
        self.server_running = True
        self.server_thread.start()
        self.start_button.configure(state="disabled")
        self.stop_button.configure(state="normal")

    def stop_server(self):
        """Stop the server."""
        if self.server_running:
            self.server_running = False
            Server.stop()  # Assuming `Server.stop()` stops the server loop
            self.start_button.configure(state="normal")
            self.stop_button.configure(state="disabled")


    def run_server(self):
        """Run the server and capture logs."""
        try:
            args = argparse.Namespace(lease_time=None, NAK=False)
            Server.start_dhcp_server(args)
        except Exception as e:
            logging.error(f"Error: {e}")

    def start_client(self):
        """Start a virtual DHCP client with user-provided or default values."""
        if not self.server_running:
            logging.error("Cannot start client. The server is not running.")
            return  # Prevent the client from starting

        threading.Thread(target=self.run_client, daemon=True).start()

    def run_client(self):
        """Pass user-provided values or defaults for IP, MAC, and Lease Time to the DHCP client."""
        # Read values from the GUI
        ip_address = self.ip_text.get("1.0", "end").strip() or None
        mac_address = self.mac_text.get("1.0", "end").strip() or None
        lease_time = self.lease_text.get("1.0", "end").strip()

        # Convert lease_time to integer if it's a valid number, otherwise keep it as None
        lease_time = int(lease_time) if lease_time.isdigit() else None

        # Construct the config dictionary
        config = {
            "requested_ip": ip_address,
            "client_id": mac_address,
            "lease_time": lease_time
        }

        # Pass the configuration to the DHCP client
        DHCP_Client.start(config)


    def update_lease_info(self, leases):
        """Update the leases display."""
        self.ip_text.configure(state="normal")
        self.mac_text.configure(state="normal")
        self.lease_text.configure(state="normal")

        # Clear existing content
        self.ip_text.delete("1.0", "end")
        self.mac_text.delete("1.0", "end")
        self.lease_text.delete("1.0", "end")

        # Add new content
        for lease in leases:
            self.ip_text.insert("end", lease["ip"] + "\n")
            self.mac_text.insert("end", lease["mac"] + "\n")
            self.lease_text.insert("end", lease["lease_time"] + "\n")

        self.ip_text.configure(state="disabled")
        self.mac_text.configure(state="disabled")
        self.lease_text.configure(state="disabled")


if __name__ == "__main__":
    app = ctk.CTk()
    DHCPServerGUI(app)
    app.mainloop()
