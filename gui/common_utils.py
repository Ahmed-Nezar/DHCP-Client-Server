import threading

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
