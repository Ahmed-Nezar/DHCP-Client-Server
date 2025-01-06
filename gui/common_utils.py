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

class LogRedirector:
    def __init__(self, text_widget):
        self.text_widget = text_widget

    def write(self, message):
        if message.strip():  # Avoid empty lines
            self.text_widget.configure(state="normal")
            self.text_widget.insert("end", message + "\n")
            self.text_widget.configure(state="disabled")
            self.text_widget.see("end")  # Scroll to the latest message

    def flush(self):
        pass  # Needed for compatibility with `sys.stdout` and `sys.stderr`
