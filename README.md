# **Dynamic Host Configuration Protocol (DHCP) Server Project**

This repository contains the implementation of a DHCP server following the guidelines of **RFC 2131** and **RFC 2132**. It allows you to manage IP leases dynamically for clients in a network. Both CLI and GUI interfaces are supported.

---

## **Installation Guide**

### **Prerequisites**
Before proceeding with the installation, ensure you have the following:

1. **Python** installed on your system. You can download it from the [official Python website](https://www.python.org/).
2. **Git** installed to clone the repository. You can download Git from [here](https://git-scm.com/).

---

### **Steps to Install**

1. **Clone the Repository**
   Open a terminal and run the following command:
   ```bash
   git clone https://github.com/mohammedYasser11/DHCP-Client-Server.git
   ```
   This will clone the project into your local directory.

2. **Navigate to the Project Directory**
   ```bash
   cd DHCP-Client-Server
   ```

3. **Install Dependencies**
   Install the required Python packages using `pip`:
   ```bash
   pip install -r requirements.txt
   ```
   This will install all necessary dependencies, including:
   - `customtkinter`
   - `cx-Freeze`
   - `pyinstaller`

---

### **Running the Project**

#### **Using the CLI**
You can run the DHCP Server or Client directly via the CLI:

- **Run the Server**
   ```bash
   python main.py --server
   ```

- **Run the Client**
   ```bash
   python main.py --client
   ```

---

#### **Using the GUI**
The project also provides a graphical user interface for ease of use:

- **Run the Server GUI**
   ```bash
   python main_gui_server.py
   ```

- **Run the Client GUI**
   ```bash
   python main_gui_client.py
   ```

> Note: The GUI requires `customtkinter` for proper functioning.

---

### **Building Executables**
To package the project into standalone executables, you can use `PyInstaller`:

- **Build the DHCP Server Executable**
   ```bash
   pyinstaller --onefile --name "DHCP Server" main_gui_server.py
   ```
---

### **Directory Structure**
The project directory is organized as follows:
```
├── README.md
├── main.py
├── main_gui_client.py
├── main_gui_server.py
├── requirements.txt
├── client/
│   └── virtual_client.py
├── config/
│   └── config.py
├── dhcp/
│   └── dhcp_server.py
├── gui/
│   ├── common_utils.py
│   ├── gui_client.py
│   └── gui_server.py
└── utils/
    └── utils.py
```

---

### **Features**

- **Dynamic IP Leasing:** Assign IP addresses dynamically from the configured pool.
- **Lease Expiry Management:** Handles lease renewals and reclaims expired IP addresses.
- **Support for Multiple Modes:**
  - Normal Operation
  - Inform Mode
  - Test Case Simulation
- **Error Handling:** Robust mechanisms to manage invalid or unauthorized requests.
- **GUI:** A clean and intuitive graphical interface for managing clients and servers.

---

### **Additional Notes**

1. **Server Modes**
   - **Default Mode:** Operates with a standard IP pool.
   - **Empty Pool Mode:** Simulates a scenario where no IPs are available.
   - **Specify Lease Time Mode:** Allows you to set custom lease durations.

2. **Logging**
   - Logs are automatically saved in `server.log` for server events and `client.log` for client activities.

3. **Testing**
   - You can run test cases using the GUI to simulate client-server interactions with different configurations.

---
