from gui.gui_server import DHCPServerGUI
import customtkinter as ctk
from multiprocessing import freeze_support


if __name__ == "__main__":
    freeze_support()
    root = ctk.CTk()
    DHCPServerGUI(root)
    root.geometry("800x600")
    root.mainloop()