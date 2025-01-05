import customtkinter as ctk
import tkinter.ttk as ttk
import threading
import argparse
import logging
import os
import sys
from dhcp.dhcp_server import Server
from client.virtual_client import DHCP_Client
import multiprocessing
import time

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

        # Dictionary to track client processes and their information
        self.client_processes = {}

        # Running Clients Button
        self.running_clients_button = ctk.CTkButton(
            self.controls_frame,
            text="Running Clients",
            command=self.open_running_clients_window
        )
        self.running_clients_button.pack(side="left", padx=5)

    def open_running_clients_window(self):
        """Open a new window to display running clients and allow termination."""
        if hasattr(self, "running_clients_window") and self.running_clients_window.winfo_exists():
            # If the window is already open, bring it to focus
            self.running_clients_window.focus()
            return

        self.running_clients_window = ctk.CTkToplevel(self.root)
        self.running_clients_window.title("Running Clients")
        self.running_clients_window.geometry("800x400")

        # Handle window close event
        self.running_clients_window.protocol("WM_DELETE_WINDOW", self.close_running_clients_window)

        # Frame for the table
        table_frame = ctk.CTkFrame(self.running_clients_window)
        table_frame.pack(fill="both", expand=True, padx=10, pady=5)

        # Table for running clients
        self.client_table = ttk.Treeview(
            table_frame,
            columns=("MAC", "IP", "Assigned Lease", "Remaining Lease"),
            show="headings",
            height=10
        )
        self.client_table.pack(fill="both", expand=True)

        # Define table headings
        self.client_table.heading("MAC", text="MAC Address")
        self.client_table.heading("IP", text="IP Address")
        self.client_table.heading("Assigned Lease", text="Assigned Lease Time")
        self.client_table.heading("Remaining Lease", text="Remaining Lease Time")

        # Define column widths
        self.client_table.column("MAC", width=200)
        self.client_table.column("IP", width=150)
        self.client_table.column("Assigned Lease", width=150)
        self.client_table.column("Remaining Lease", width=150)

        # Frame for logs
        logs_frame = ctk.CTkFrame(self.running_clients_window)
        logs_frame.pack(fill="both", expand=False, padx=10, pady=5)

        ctk.CTkLabel(logs_frame, text="Logs").pack(anchor="w")

        # Textbox to display logs
        self.clients_logs_text = ctk.CTkTextbox(logs_frame, state="disabled", height=5)
        self.clients_logs_text.pack(fill="both", expand=True)

        # Frame for termination controls
        controls_frame = ctk.CTkFrame(self.running_clients_window)
        controls_frame.pack(fill="x", pady=10)

        ctk.CTkLabel(controls_frame, text="Enter MAC Address to Terminate:").pack(side="left", padx=5)
        self.mac_terminate_entry = ctk.CTkEntry(controls_frame)
        self.mac_terminate_entry.pack(side="left", padx=5)

        terminate_button = ctk.CTkButton(
            controls_frame,
            text="Terminate Client",
            command=self.terminate_client
        )
        terminate_button.pack(side="left", padx=5)

        # Start periodic updates
        self.update_running_clients_table()
        self.poll_running_clients_logs()


    def update_running_clients_table(self):
        """Update the table with information about running clients."""
        if not hasattr(self, "running_clients_window") or not self.running_clients_window.winfo_exists():
            return  # Stop if the window no longer exists

        # Clear the current table content
        for row in self.client_table.get_children():
            self.client_table.delete(row)

        # Populate table with updated client information
        for mac_address, client_data in self.client_processes.items():
            _, queue = client_data

            if not queue.empty():
                # Extract the latest client details
                client_status = queue.get().split(", ")
                mac = client_status[0].split(": ")[1]
                ip = client_status[1].split(": ")[1]
                assigned_lease = client_status[2].split(": ")[1]
                remaining_lease = client_status[3].split(": ")[1]

                # Add to table
                self.client_table.insert(
                    "",
                    "end",
                    values=(mac, ip, assigned_lease, remaining_lease)
                )

        # Schedule the next update
        self.root.after(1000, self.update_running_clients_table)

    def close_running_clients_window(self):
        """Clean up callbacks when the running clients window is closed."""
        if hasattr(self, "running_clients_window"):
            self.running_clients_window.destroy()
            del self.running_clients_window

    def poll_running_clients_logs(self):
        """Update the logs for running clients."""
        if not hasattr(self, "running_clients_window") or not self.running_clients_window.winfo_exists():
            return  # Stop if the window no longer exists

        self.clients_logs_text.configure(state="normal")

        # Append any new logs to the textbox
        for _, client_data in self.client_processes.items():
            _, queue = client_data
            while not queue.empty():
                log_message = queue.get()
                self.clients_logs_text.insert("end", log_message + "\n")

        self.clients_logs_text.configure(state="disabled")
        self.clients_logs_text.see("end")

        # Schedule the next log poll
        self.root.after(500, self.poll_running_clients_logs)


    def terminate_client(self):
        """Terminate a client based on the provided MAC address."""
        mac_address = self.mac_terminate_entry.get().strip()
        if not mac_address:
            self.clients_logs_text.configure(state="normal")
            self.clients_logs_text.insert("end", "Error: No MAC address provided for termination.\n")
            self.clients_logs_text.configure(state="disabled")
            return

        # Terminate the process associated with the given MAC address
        if mac_address in self.client_processes:
            process, _ = self.client_processes.pop(mac_address)
            if process.is_alive():
                process.terminate()
                process.join()
            self.clients_logs_text.configure(state="normal")
            self.clients_logs_text.insert("end", f"Client {mac_address} terminated successfully.\n")
            self.clients_logs_text.configure(state="disabled")
        else:
            self.clients_logs_text.configure(state="normal")
            self.clients_logs_text.insert("end", f"Error: No running client found with MAC address {mac_address}.\n")
            self.clients_logs_text.configure(state="disabled")
            
                        
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

        # Prepare client options based on mode
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
            if not requested_ip or not client_id or not lease_time:
                self.client_logs_text.configure(state="normal")
                self.client_logs_text.insert("end", "Error: Missing required Test Case inputs.\n")
                self.client_logs_text.configure(state="disabled")
                return

            client_options = {
                "client_mac": client_id,
                "requested_ip": requested_ip,
                "lease_time": int(lease_time) if lease_time.isdigit() else 0,
                "escape_discover": 0,
                "inform": 0
            }

        # Create a queue for communication with the client process
        log_queue = multiprocessing.Queue()

        # Start a new process for the client
        client_process = multiprocessing.Process(target=run_client, args=(client_options, log_queue))
        client_process.start()

        # Add the process and queue to the client processes dictionary
        self.client_processes[client_options["client_mac"]] = (client_process, log_queue)

        # Notify the GUI
        self.client_logs_text.configure(state="normal")
        self.client_logs_text.insert("end", f"Started client with MAC {client_options['client_mac']}.\n")
        self.client_logs_text.configure(state="disabled")

        # Begin polling logs
        self.poll_client_logs(client_options["client_mac"])


    def poll_client_logs(self, mac_address):
        """Poll logs for a specific client and update the GUI."""
        if mac_address in self.client_processes:
            process, queue = self.client_processes[mac_address]

            # Fetch logs from the client process queue
            while not queue.empty():
                log_message = queue.get()
                self.client_logs_text.configure(state="normal")
                self.client_logs_text.insert("end", log_message + "\n")
                self.client_logs_text.configure(state="disabled")
                self.client_logs_text.see("end")

            # Continue polling if the process is still running
            if process.is_alive():
                self.root.after(100, lambda: self.poll_client_logs(mac_address))
            else:
                # Process has exited; check remaining logs
                while not queue.empty():
                    log_message = queue.get()
                    self.client_logs_text.configure(state="normal")
                    self.client_logs_text.insert("end", log_message + "\n")
                    self.client_logs_text.configure(state="disabled")
                    self.client_logs_text.see("end")

                # Notify GUI about process termination
                self.client_logs_text.configure(state="normal")
                self.client_logs_text.insert("end", f"Client {mac_address} has stopped.\n")
                self.client_logs_text.configure(state="disabled")

def run_client(client_options, log_queue):
    """Run a DHCP client with the given options and send updates to the GUI."""
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
        client = DHCP_Client()
        # Simulate client operation
        client.start(client_options)
        
        # Example periodic log updates
        remaining_lease_time = client_options["lease_time"]
        while remaining_lease_time > 0:
            log_queue.put(
                f"MAC: {client_options['client_mac']}, "
                f"IP: {client_options['requested_ip']}, "
                f"Lease: {client_options['lease_time']}s, "
                f"Remaining: {remaining_lease_time}s"
            )
            remaining_lease_time -= 1
    except Exception as e:
        log_queue.put(f"Error for client {client_options['client_mac']}: {e}")




if __name__ == "__main__":
    app = ctk.CTk()
    DHCPServerGUI(app)
    app.mainloop()