import customtkinter as ctk
import threading
import argparse
import logging
import os
import sys
from dhcp.dhcp_server import Server
from client.virtual_client import DHCP_Client
import multiprocessing

class TextRedirector:
    """Redirect output streams to a text widget."""
    def __init__(self, text_widget, tag="stdout"):
        self.text_widget = text_widget
        self.tag = tag
        self.lock = threading.Lock()

    def write(self, message):
        with self.lock:
            self.text_widget.configure(state="normal")
            self.text_widget.insert("end", message)
            self.text_widget.configure(state="disabled")
            self.text_widget.see("end")

    def flush(self):
        pass

class DHCPServerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("DHCP Server Manager")
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        # Frame for controls (Start/Stop Server and Client)
        self.controls_frame = ctk.CTkFrame(self.root)
        self.controls_frame.pack(pady=10)

        # Start/Stop Server Buttons
        self.start_button = ctk.CTkButton(self.controls_frame, text="Start Server", command=self.start_server)
        self.start_button.pack(side="left", padx=5)
        self.stop_button = ctk.CTkButton(self.controls_frame, text="Stop Server", state="disabled", command=self.stop_server)
        self.stop_button.pack(side="left", padx=5)

        # Start Client Button
        self.start_client_button = ctk.CTkButton(self.controls_frame, text="Start Client", command=self.start_client)
        self.start_client_button.pack(side="left", padx=5)

        # Leases Section
        self.leases_frame = ctk.CTkFrame(self.root)
        self.leases_frame.pack(padx=10, pady=10, fill="both", expand=True)

        # Server and Client Configuration (side-by-side layout)
        self.configuration_frame = ctk.CTkFrame(self.leases_frame)
        self.configuration_frame.pack(pady=10, fill="x", expand=True)

        # Server Configuration
        server_config_frame = ctk.CTkFrame(self.configuration_frame)
        server_config_frame.pack(side="left", padx=10, pady=10, fill="both", expand=True)

        ctk.CTkLabel(server_config_frame, text="Server Configuration").pack(anchor="w")
        self.server_mode = ctk.StringVar(value="")  # No default selection
        
        # Radio buttons for server configuration Normal, Empty Pool, Specify Lease Time
        ctk.CTkRadioButton(server_config_frame, text="Default", variable=self.server_mode, value="normal").pack(anchor="w")
        ctk.CTkRadioButton(server_config_frame, text="Empty Pool", variable=self.server_mode, value="empty_pool").pack(anchor="w")
        ctk.CTkRadioButton(server_config_frame, text="Specify Lease Time", variable=self.server_mode, value="specify_lease").pack(anchor="w")

        # Lease Time Entry for Specify Lease Time
        self.lease_time_label = ctk.CTkLabel(server_config_frame, text="Lease Time (seconds)")
        self.lease_time_entry = ctk.CTkEntry(server_config_frame)
        self.lease_time_label.pack_forget()
        self.lease_time_entry.pack_forget()

        # Toggle Lease Time Entry Visibility
        def on_server_mode_change():
            if self.server_mode.get() == "specify_lease":
                self.lease_time_label.pack(anchor="w")
                self.lease_time_entry.pack(anchor="w")
            else:
                self.lease_time_label.pack_forget()
                self.lease_time_entry.pack_forget()

        self.server_mode.trace("w", lambda *args: on_server_mode_change())

        # Client Configuration
        client_config_frame = ctk.CTkFrame(self.configuration_frame)
        client_config_frame.pack(side="left", padx=10, pady=10, fill="both", expand=True)

        ctk.CTkLabel(client_config_frame, text="Client Configuration").pack(anchor="w")
        self.client_mode = ctk.StringVar(value="")
        ctk.CTkRadioButton(client_config_frame, text="Inform", variable=self.client_mode, value="inform").pack(anchor="w")
        ctk.CTkRadioButton(client_config_frame, text="Test Case", variable=self.client_mode, value="test_case").pack(anchor="w")

        # Test Case Configuration Inputs
        self.ip_label = ctk.CTkLabel(client_config_frame, text="Requested IP Address")
        self.ip_entry = ctk.CTkEntry(client_config_frame)
        self.mac_label = ctk.CTkLabel(client_config_frame, text="Client MAC Address")
        self.mac_entry = ctk.CTkEntry(client_config_frame)
        self.lease_label = ctk.CTkLabel(client_config_frame, text="Lease Time (seconds)")
        self.lease_entry = ctk.CTkEntry(client_config_frame)

        # Initially hide Test Case inputs
        self.ip_label.pack_forget()
        self.ip_entry.pack_forget()
        self.mac_label.pack_forget()
        self.mac_entry.pack_forget()
        self.lease_label.pack_forget()
        self.lease_entry.pack_forget()

        # Toggle Test Case Inputs Visibility
        def on_client_mode_change():
            if self.client_mode.get() == "test_case":
                self.ip_label.pack(anchor="w")
                self.ip_entry.pack(anchor="w")
                self.mac_label.pack(anchor="w")
                self.mac_entry.pack(anchor="w")
                self.lease_label.pack(anchor="w")
                self.lease_entry.pack(anchor="w")
            else:
                self.ip_label.pack_forget()
                self.ip_entry.pack_forget()
                self.mac_label.pack_forget()
                self.mac_entry.pack_forget()
                self.lease_label.pack_forget()
                self.lease_entry.pack_forget()

        self.client_mode.trace("w", lambda *args: on_client_mode_change())

        # Available IPs Section
        self.available_ips_frame = ctk.CTkFrame(self.root)
        self.available_ips_frame.pack(padx=10, pady=10, fill="both", expand=True)
        ctk.CTkLabel(self.available_ips_frame, text="Available IPs").pack(anchor="w")

        self.available_ips_text = ctk.CTkTextbox(self.available_ips_frame, height=10, state="disabled")
        self.available_ips_text.pack(fill="both", expand=True)

        self.load_available_ips()

        # Server Logs Section
        self.server_logs_frame = ctk.CTkFrame(self.root)
        self.server_logs_frame.pack(padx=10, pady=10, fill="both", expand=True)
        ctk.CTkLabel(self.server_logs_frame, text="Server Logs").pack(anchor="w")

        self.server_logs_text = ctk.CTkTextbox(self.server_logs_frame, height=10, state="disabled")
        self.server_logs_text.pack(fill="both", expand=True)

        # Client Logs Section
        self.client_logs_frame = ctk.CTkFrame(self.root)
        self.client_logs_frame.pack(padx=10, pady=10, fill="both", expand=True)
        ctk.CTkLabel(self.client_logs_frame, text="Client Logs").pack(anchor="w")

        self.client_logs_text = ctk.CTkTextbox(self.client_logs_frame, height=10, state="disabled")
        self.client_logs_text.pack(fill="both", expand=True)

        # Redirect stdout and stderr for Server Logs
        self.server_log_redirector = TextRedirector(self.server_logs_text, "stdout")
        self.server_error_redirector = TextRedirector(self.server_logs_text, "stderr")

        # Redirect stdout and stderr for Client Logs
        self.client_log_redirector = TextRedirector(self.client_logs_text, "stdout")
        self.client_error_redirector = TextRedirector(self.client_logs_text, "stderr")


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
            logging.error("You must select a server configuration option before starting the server.")
            self.server_logs_text.configure(state="normal")
            self.server_logs_text.insert("end", "Error: No server configuration selected.\n")
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
            logging.info(f"Starting the server with specified lease time (--lease-time={lease_time}).")
            server_args = argparse.Namespace(server=True, lease_time=lease_time, NAK=False)
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

    def start_client(self):
        """Start the client with the provided configuration in a new process."""
        if not self.client_mode.get() or not self.server_running:
            self.client_logs_text.configure(state="normal")
            self.client_logs_text.insert("end", "Error: No client configuration selected or server not running.\n")
            self.client_logs_text.configure(state="disabled")
            return

        if self.client_mode.get() == "inform":
            client_options = {
                "client_mac": "00:11:22:33:44:55",  # Default INFORM MAC
                "requested_ip": "192.168.1.10",     # Default INFORM IP
                "lease_time": 2003,                 # Default INFORM Lease Time
                "escape_discover": 0,
                "inform": 1
            }
        elif self.client_mode.get() == "test_case":
            requested_ip = self.ip_entry.get().strip()
            client_id = self.mac_entry.get().strip()
            lease_time = self.lease_entry.get().strip()
            if not requested_ip and not client_id and not lease_time:
                self.client_logs_text.configure(state="normal")
                self.client_logs_text.insert("end", "Error: No inputs provided for Test Case mode.\n")
                self.client_logs_text.configure(state="disabled")
                return

            client_options = {
                "client_mac": client_id if client_id else "",
                "requested_ip": requested_ip if requested_ip else "",
                "lease_time": int(lease_time) if lease_time.isdigit() else "",
                "escape_discover": 0,
                "inform": 0
            }

        # Create a queue for log communication
        self.client_log_queue = multiprocessing.Queue()

        # Start the client process with the queue
        self.client_process = multiprocessing.Process(target=run_client, args=(client_options, self.client_log_queue))
        self.client_process.start()

        # Poll logs from the client process
        self.poll_client_logs()

    def poll_client_logs(self):
        """Poll logs from the client process and display them in the GUI."""
        while not self.client_log_queue.empty():
            log_message = self.client_log_queue.get()
            self.client_logs_text.configure(state="normal")
            self.client_logs_text.insert("end", log_message + "\n")
            self.client_logs_text.configure(state="disabled")
            self.client_logs_text.see("end")
        if self.client_process.is_alive():  # Keep polling while the process is running
            self.root.after(100, self.poll_client_logs)
        else:
            # Check if there are any remaining logs after the process exits
            while not self.client_log_queue.empty():
                log_message = self.client_log_queue.get()
                self.client_logs_text.configure(state="normal")
                self.client_logs_text.insert("end", log_message + "\n")
                self.client_logs_text.configure(state="disabled")
                self.client_logs_text.see("end")

def run_client(client_options, log_queue):
    """Run a DHCP client with the given options and redirect logs to the main process."""
    class QueueWriter:
        def __init__(self, queue):
            self.queue = queue

        def write(self, message):
            if message.strip():  # Avoid logging empty lines
                self.queue.put(message)

        def flush(self):
            pass

    # Redirect stdout and stderr to the log queue
    sys.stdout = QueueWriter(log_queue)
    sys.stderr = QueueWriter(log_queue)

    try:
        DHCP_Client().start(client_options)
    except Exception as e:
        print(f"Error starting client: {e}")



if __name__ == "__main__":
    app = ctk.CTk()
    DHCPServerGUI(app)
    app.mainloop()