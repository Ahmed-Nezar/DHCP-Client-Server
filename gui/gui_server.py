import customtkinter as ctk
import threading
import argparse
import logging
import os
import sys
from dhcp.dhcp_server import Server
from gui.common_utils import TextRedirector


class DHCPServerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("DHCP Server Manager")
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        # Frame for controls (Start/Stop Server and Client)
        self.controls_frame = ctk.CTkFrame(self.root)
        self.controls_frame.pack(pady=10)

        self.running_clients = {}

        # Start/Stop Server Buttons
        self.start_button = ctk.CTkButton(
            self.controls_frame, text="Start Server", command=self.start_server
        )
        self.start_button.pack(side="left", padx=5)
        self.stop_button = ctk.CTkButton(
            self.controls_frame,
            text="Stop Server",
            state="disabled",
            command=self.stop_server,
        )
        self.stop_button.pack(side="left", padx=5)

        # Leases Section
        self.leases_frame = ctk.CTkFrame(self.root)
        self.leases_frame.pack(padx=10, pady=10, fill="both", expand=True)

        # Server and Client Configuration (side-by-side layout)
        self.configuration_frame = ctk.CTkFrame(self.leases_frame)
        self.configuration_frame.pack(pady=10, fill="x", expand=True)

        # Server Configuration
        server_config_frame = ctk.CTkFrame(self.configuration_frame)
        server_config_frame.pack(
            side="left", padx=10, pady=10, fill="both", expand=True
        )

        ctk.CTkLabel(server_config_frame, text="Server Configuration").pack(anchor="w")
        self.server_mode = ctk.StringVar(value="")  # No default selection

        # Radio buttons for server configuration Normal, Empty Pool, Specify Lease Time
        ctk.CTkRadioButton(
            server_config_frame,
            text="Default",
            variable=self.server_mode,
            value="normal",
        ).pack(anchor="w")
        ctk.CTkRadioButton(
            server_config_frame,
            text="Empty Pool",
            variable=self.server_mode,
            value="empty_pool",
        ).pack(anchor="w")
        ctk.CTkRadioButton(
            server_config_frame,
            text="Specify Lease Time",
            variable=self.server_mode,
            value="specify_lease",
        ).pack(anchor="w")

        # Lease Time Entry for Specify Lease Time
        self.lease_time_label = ctk.CTkLabel(
            server_config_frame, text="Lease Time (seconds)"
        )
        self.lease_time_entry = ctk.CTkEntry(server_config_frame)

        # Toggle Lease Time Entry Visibility
        def on_server_mode_change():
            if self.server_mode.get() == "specify_lease":
                self.lease_time_label.pack(anchor="w")
                self.lease_time_entry.pack(anchor="w")
            else:
                self.lease_time_label.pack_forget()
                self.lease_time_entry.pack_forget()

        self.server_mode.trace("w", lambda *args: on_server_mode_change())

        # Available IPs Section
        self.available_ips_frame = ctk.CTkFrame(self.root)
        self.available_ips_frame.pack(padx=10, pady=10, fill="both", expand=True)
        ctk.CTkLabel(self.available_ips_frame, text="Available IPs").pack(anchor="w")

        self.available_ips_text = ctk.CTkTextbox(
            self.available_ips_frame, height=10, state="disabled"
        )
        self.available_ips_text.pack(fill="both", expand=True)

        self.load_available_ips()

        # Server Logs Section
        self.server_logs_frame = ctk.CTkFrame(self.root)
        self.server_logs_frame.pack(padx=10, pady=10, fill="both", expand=True)
        ctk.CTkLabel(self.server_logs_frame, text="Server Logs").pack(anchor="w")

        self.server_logs_text = ctk.CTkTextbox(
            self.server_logs_frame, height=10, state="disabled"
        )
        self.server_logs_text.pack(fill="both", expand=True)

        # Redirect stdout and stderr for Server Logs
        self.server_log_redirector = TextRedirector(self.server_logs_text, "stdout")
        self.server_error_redirector = TextRedirector(self.server_logs_text, "stderr")

        self.server_thread = None
        self.server_running = False

    def load_available_ips(self):
        """Load available IPs from a file and update the GUI."""
        ip_pool_path = os.path.join(os.path.dirname(__file__), "../dhcp/ip_pool.txt")
        self.available_ips_text.configure(state="normal")
        self.available_ips_text.delete("1.0", "end")
        try:
            if os.path.exists(ip_pool_path):
                with open(ip_pool_path, "r") as f:
                    ips = [line.strip() for line in f if line.strip()]
                formatted_ips = "\n".join(ips) if ips else "No available IPs."
            else:
                formatted_ips = "IP pool file not found."
        except Exception as e:
            formatted_ips = f"Error loading IPs: {e}"
        self.available_ips_text.insert("end", formatted_ips)
        self.available_ips_text.configure(state="disabled")
        self.root.after(2000, self.load_available_ips)

    def start_server(self):
        """Start the server in a new thread."""
        lease_time = None

        # Check if a radio button is selected
        if not self.server_mode.get():
            logging.error(
                "You must select a server configuration option before starting the server."
            )
            self.server_logs_text.configure(state="normal")
            self.server_logs_text.insert(
                "end", "Error: No server configuration selected.\n"
            )
            self.server_logs_text.configure(state="disabled")
            return

        # Configure the server behavior based on the selected radio button
        if self.server_mode.get() == "empty_pool":
            logging.info("Starting the server in Empty Pool mode (--NAK).")
            server_args = argparse.Namespace(server=True, lease_time=None, NAK=True)
        elif self.server_mode.get() == "specify_lease":
            lease_time = self.lease_time_entry.get().strip()
            if not lease_time.isdigit():
                logging.error("Invalid lease time. Please enter a valid number.")
                self.server_logs_text.configure(state="normal")
                self.server_logs_text.insert("end", "Error: Invalid lease time.\n")
                self.server_logs_text.configure(state="disabled")
                return
            lease_time = int(lease_time)
            logging.info(
                f"Starting the server with specified lease time (--lease-time={lease_time})."
            )
            server_args = argparse.Namespace(
                server=True, lease_time=lease_time, NAK=False
            )
        elif self.server_mode.get() == "normal":
            logging.info("Starting the server in Normal mode.")
            server_args = argparse.Namespace(server=True, lease_time=None, NAK=False)

        # Redirect stdout and stderr for the server logs
        sys.stdout = self.server_log_redirector
        sys.stderr = self.server_error_redirector

        # Start the server in a new thread
        self.server_thread = threading.Thread(
            target=lambda: Server.start_dhcp_server(server_args),
            daemon=True,
        )
        self.server_running = True
        self.server_thread.start()
        self.start_button.configure(state="disabled")
        self.stop_button.configure(state="normal")

        # Disable the Server Configuration section
        for widget in self.configuration_frame.winfo_children()[0].winfo_children():
            widget.configure(state="disabled")

    def stop_server(self):
        """Stop the server."""
        if self.server_running:
            self.server_running = False
            Server.stop()
            self.start_button.configure(state="normal")
            self.stop_button.configure(state="disabled")

            # Re-enable the Server Configuration section
            for widget in self.configuration_frame.winfo_children()[0].winfo_children():
                widget.configure(state="normal")

            # Reset stdout and stderr
            sys.stdout = sys.__stdout__
            sys.stderr = sys.__stderr__

