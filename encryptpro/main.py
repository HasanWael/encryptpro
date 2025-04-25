# encryptpro/main.py
import customtkinter as ctk
import sys
import os

# Add the parent directory (encryptpro_project) to the Python path
# This allows importing the 'encryptpro' package
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.insert(0, parent_dir)

# Now import from the package
from encryptpro.gui import ModernEncryptionApp

def run_application():
    """Sets up and runs the EncryptPro application."""
    ctk.set_appearance_mode("System") # System, Dark, Light
    ctk.set_default_color_theme("blue") # blue, dark-blue, green

    app = ModernEncryptionApp()
    # Set initial status after GUI is built
    app.update_status("EncryptPro ready.", "green")
    app.run()

if __name__ == "__main__":
    run_application()