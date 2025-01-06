from cx_Freeze import setup, Executable

# Define the executable
executables = [
    Executable("main_gui_server.py", target_name="DHCP Server.exe", base="Win32GUI"),
    Executable("main_gui_client.py", target_name="DHCP Client.exe", base="Win32GUI"),
]

# Setup configurations
setup(
    name="DHCP Server/Client",
    version="1.0",
    description="Your application description",
    executables=executables,
)
