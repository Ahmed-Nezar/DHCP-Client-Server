from cx_Freeze import setup, Executable

# Define the executable
executables = [
    Executable("main_gui_server.py", target_name="DHCP Server.exe", base="Win32GUI"),
]

# Setup configurations
setup(
    name="DHCP Server",
    version="1.0",
    description="Your application description",
    executables=executables,
)
