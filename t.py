import tkinter as tk
from tkinter import messagebox

class CopyableMessageDialog:
    def __init__(self, title, message):
        self.root = tk.Toplevel()
        self.root.title(title)
        self.root.resizable(False, False) # Prevent resizing

        # Create a Text widget for the message
        self.text_widget = tk.Text(self.root, wrap="word", height=10, width=50, state="normal")
        self.text_widget.insert(tk.END, message)
        self.text_widget.config(state="disabled") # Make it read-only
        self.text_widget.pack(padx=10, pady=10)

        # Add an "OK" button to close the dialog
        ok_button = tk.Button(self.root, text="OK", command=self.root.destroy)
        ok_button.pack(pady=5)

        # Make the dialog modal
        self.root.grab_set()
        self.root.wait_window(self.root)

def show_copyable_message(title, message):
    CopyableMessageDialog(title, message)

if __name__ == "__main__":
    root = tk.Tk()
    root.withdraw() # Hide the main Tkinter window

    message_to_copy = "This is a long message that the user might want to copy. It contains important information and details that should be easily accessible for copying and pasting into other applications or documents."
    show_copyable_message("Information to Copy", message_to_copy)

    messagebox.showinfo("Operation Complete", "The copyable message dialog has been closed.")
    root.destroy()