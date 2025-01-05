import customtkinter as ctk
import sys
from client.virtual_client import DHCP_Client
import multiprocessing
from queue import Empty


class DHCPClientGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("DHCP Client Manager")
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        # Frame for controls (Start/Stop Server and Client)
        self.controls_frame = ctk.CTkFrame(self.root)
        self.controls_frame.pack(pady=10)
        
        self.running_clients = {}

        # Start Client Button
        self.start_client_button = ctk.CTkButton(self.controls_frame, text="Start Client", command=self.start_client)
        self.start_client_button.pack(side="left", padx=5)

        # Leases Section
        self.leases_frame = ctk.CTkFrame(self.root)
        self.leases_frame.pack(padx=10, pady=10, fill="both", expand=True)

        # Server and Client Configuration (side-by-side layout)
        self.configuration_frame = ctk.CTkFrame(self.leases_frame)
        self.configuration_frame.pack(pady=10, fill="x", expand=True)

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

        # Running Clients Section
        self.running_clients_frame = ctk.CTkFrame(self.root)
        self.running_clients_frame.pack(padx=10, pady=10, fill="both", expand=True)
        ctk.CTkLabel(self.running_clients_frame, text="Running Clients").pack(anchor="w")

        self.running_clients_table = ctk.CTkFrame(self.running_clients_frame)
        self.running_clients_table.pack(fill="both", expand=True)

        # Table headers
        ctk.CTkLabel(self.running_clients_table, text="MAC Address", width=20).grid(row=0, column=0, padx=5, pady=5)
        ctk.CTkLabel(self.running_clients_table, text="IP Address", width=20).grid(row=0, column=1, padx=5, pady=5)
        ctk.CTkLabel(self.running_clients_table, text="Lease Time", width=20).grid(row=0, column=2, padx=5, pady=5)

        # Client Logs Section
        self.client_logs_frame = ctk.CTkFrame(self.root)
        self.client_logs_frame.pack(padx=10, pady=10, fill="both", expand=True)
        ctk.CTkLabel(self.client_logs_frame, text="Client Logs").pack(anchor="w")

        self.client_logs_text = ctk.CTkTextbox(self.client_logs_frame, height=10, state="disabled")
        self.client_logs_text.pack(fill="both", expand=True)

    def update_running_clients_table(self):
        """Refresh the running clients table."""
        for widget in self.running_clients_table.winfo_children()[3:]:  # Skip header widgets
            widget.destroy()

        for idx, (mac, client_info) in enumerate(self.running_clients.items(), start=1):
            ctk.CTkLabel(self.running_clients_table, text=mac).grid(row=idx, column=0, padx=5, pady=5)
            ctk.CTkLabel(self.running_clients_table, text=client_info['ip']).grid(row=idx, column=1, padx=5, pady=5)
            ctk.CTkLabel(self.running_clients_table, text=client_info['lease_time']).grid(row=idx, column=2, padx=5, pady=5)

    def start_client(self):
        """Start the client with the provided configuration in a new process."""
        if not self.client_mode.get():
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

        # Poll logs to get the IP dynamically
        def poll_for_ip():
            """Continuously poll for IP address in the logs."""
            try:
                while True:
                    log_message = self.client_log_queue.get(timeout=1)
                    self.client_logs_text.configure(state="normal")
                    self.client_logs_text.insert("end", log_message + "\n")
                    self.client_logs_text.configure(state="disabled")
                    self.client_logs_text.see("end")

                    if "Leased IP:" in log_message:  # Extract IP from log message
                        ip_address = log_message.split(":")[-1].strip()
                        self.running_clients[client_options['client_mac']] = {
                            'process': self.client_process,
                            'ip': ip_address,
                            'lease_time': client_options['lease_time'],
                            'log_queue': self.client_log_queue
                        }
                        self.update_running_clients_table()
                        break
            except Empty:
                if not self.client_process.is_alive():
                    return
                self.root.after(100, poll_for_ip)

        self.root.after(100, poll_for_ip)

    def poll_client_logs(self):
        """Poll logs from the client process and display them in the GUI."""
        try:
            while True:
                log_message = self.client_log_queue.get_nowait()
                self.client_logs_text.configure(state="normal")
                self.client_logs_text.insert("end", log_message + "\n")
                self.client_logs_text.configure(state="disabled")
                self.client_logs_text.see("end")
        except Empty:
            if self.client_process.is_alive():
                self.root.after(100, self.poll_client_logs)


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
