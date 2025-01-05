from gui.gui_server import DHCPServerGUI
import customtkinter as ctk

if __name__ == "__main__":
    root = ctk.CTk()
    DHCPServerGUI(root)
    root.geometry("800x600")
    root.mainloop()