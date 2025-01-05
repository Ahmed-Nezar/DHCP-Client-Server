from gui.gui_client import DHCPClientGUI
import customtkinter as ctk

if __name__ == "__main__":
    root = ctk.CTk()
    DHCPClientGUI(root)
    root.geometry("800x600")
    root.mainloop()