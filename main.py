import tkinter as tk
from src.gui import SecureFileLockerGUI
import os

def main():
    """Initialize and run the Secure File Locker application."""
    
    # Create data directory if it doesn't exist
    os.makedirs('data', exist_ok=True)
    
    # Create main window
    root = tk.Tk()
    
    # Set window icon and title
    root.title("Secure File Locker 🔐")
    
    # Set minimum window size
    root.minsize(900, 600)
    
    # Configure window scaling
    root.columnconfigure(0, weight=1)
    root.rowconfigure(0, weight=1)
    
    # Create main application
    app = SecureFileLockerGUI(root)
    
    # Start the application
    root.mainloop()

if __name__ == "__main__":
    main()
