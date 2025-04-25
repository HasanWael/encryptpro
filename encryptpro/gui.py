# encryptpro/gui.py
import customtkinter as ctk
import tkinter.filedialog
import tkinter.messagebox
import threading
import time
import os
import string

from .logic import EncryptionLogic
from .utils import generate_appropriate_key

try:
    from PIL import Image
except ImportError:
    Image = None # Flag that Pillow is not available
    print("Warning: Pillow library not found. Icons will not be loaded.")

ICON_DIR = os.path.join(os.path.dirname(__file__), "icons")


class ModernEncryptionApp:
    def __init__(self):
        self.root = ctk.CTk()
        self.root.title("EncryptPro - Modern Encryption Tool")
        self.root.geometry("1100x720")

        self.root.grid_columnconfigure(1, weight=1)
        self.root.grid_columnconfigure(0, weight=0)
        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_rowconfigure(1, weight=0)

        self.icons = {}  # Dictionary to hold loaded PhotoImage objects
        self._load_icons()  # Load icons during initialization

        self.setup_variables()
        self.is_processing = False
        self.create_interface()


    def setup_variables(self):
        self.algorithm_var = ctk.StringVar(value="OTP")
        self.operation_var = ctk.StringVar(value="encrypt")
        self.current_input_file = None
        self.current_output_file = None
        self.methods = {
            "OTP": True, "Caesar": True, "ROT13": False, "Playfair": True,
            "Transposition": True, "Substitution": True, "Rail Fence": True
        }
        self.process_button = None
        self.key_entry = None
        self.generate_key_button = None
        self.save_button = None
        self.output_textbox = None
        self.input_textbox = None
        self.status_label = None
        self.status_indicator = None
        self.sidebar_buttons = {}
        self.operation_frame = None
        self.status_frame = None
        self.bottom_frame = None
        self.exit_button = None
        self.theme_toggle_button = None

    def create_interface(self):
        self.create_sidebar()
        self.create_main_area()
        # Remove the separate create_exit_button call
        self.update_ui_for_operation()
        self.update_key_entry_state()

    def create_sidebar(self):
        # Sidebar takes up row 0, column 0
        sidebar = ctk.CTkFrame(self.root, width=230, corner_radius=0)
        sidebar.grid(row=0, column=0, rowspan=1, sticky="nsew")  # Use nsew to fill vertically too
        sidebar.grid_propagate(False)

        logo_label = ctk.CTkLabel(sidebar, text="EncryptPro", font=ctk.CTkFont(size=24, weight="bold"))
        logo_label.pack(pady=(20, 25), padx=20)

        # --- Method Selection ---
        method_frame_label = ctk.CTkLabel(sidebar, text="Algorithm", anchor="w", font=ctk.CTkFont(weight="bold"))
        method_frame_label.pack(fill="x", padx=20, pady=(0, 5))

        method_frame = ctk.CTkScrollableFrame(sidebar, fg_color="transparent", label_text="")
        method_frame.pack(fill="x", expand=True, padx=10, pady=5)  # Allow frame to expand vertically

        self.sidebar_buttons.clear()
        for method in self.methods.keys():
            btn = ctk.CTkButton(
                method_frame, text=method, height=35, anchor="w",
                command=lambda m=method: self.select_method(m),
                fg_color="transparent", text_color=("gray10", "gray90"),
                hover_color=("gray70", "gray30"), corner_radius=5)
            btn.pack(fill="x", pady=2, padx=5)
            self.sidebar_buttons[method] = btn

        if self.algorithm_var.get() in self.sidebar_buttons:
            self.sidebar_buttons[self.algorithm_var.get()].configure(fg_color=("gray75", "gray25"))

        # --- Operation Selection ---
        op_frame_label = ctk.CTkLabel(sidebar, text="Operation", anchor="w", font=ctk.CTkFont(weight="bold"))
        op_frame_label.pack(fill="x", padx=20, pady=(15, 5))

        self.operation_frame = ctk.CTkFrame(sidebar, fg_color="transparent")
        self.operation_frame.pack(fill="x", pady=0, padx=20)

        encrypt_radio = ctk.CTkRadioButton(
            self.operation_frame, text="Encrypt", variable=self.operation_var,
            value="encrypt", command=self.update_ui_for_operation)
        encrypt_radio.pack(anchor="w", pady=5, side="left")

        decrypt_radio = ctk.CTkRadioButton(
            self.operation_frame, text="Decrypt", variable=self.operation_var,
            value="decrypt", command=self.update_ui_for_operation)
        decrypt_radio.pack(anchor="w", pady=5, side="right", padx=(10, 0))

        # --- Combined Theme Buttons Section (CORRECTED) ---
        appearance_label = ctk.CTkLabel(sidebar, text="Appearance Mode", anchor="w",  # Changed anchor to 'w'
                                        font=ctk.CTkFont(weight="bold"))
        # Pack label first
        appearance_label.pack(fill="x", padx=20, pady=(20, 5))  # Padding above and below label

        # Create ONE frame to hold the two buttons
        theme_button_frame = ctk.CTkFrame(sidebar, fg_color="transparent")
        # Pack this container frame
        theme_button_frame.pack(fill="x", padx=15, pady=(0, 15))  # Padding around the frame
        # Configure 2 columns inside THIS frame to share the space
        theme_button_frame.grid_columnconfigure((0, 1), weight=1)

        # --- Create the Light/Dark Toggle Button ---
        initial_mode = ctk.get_appearance_mode()
        if initial_mode == "Dark":
            initial_text = " Light Mode"
            initial_icon = self.icons.get("sun")
        else:
            initial_text = " Dark Mode"
            initial_icon = self.icons.get("moon")

        self.theme_toggle_button = ctk.CTkButton(
            master=theme_button_frame,  # <<<<<< Set master to the FRAME
            text=initial_text,
            image=initial_icon,
            compound="left",
            height=30,
            anchor="center",
            command=self._toggle_appearance_mode,
            corner_radius=6,  # Example styling
            # fg_color=("gray75", "gray25"), # Optional shared style
            # hover_color=("gray70", "gray30")
        )
        # Grid the toggle button in the first column OF THE FRAME
        self.theme_toggle_button.grid(row=0, column=0, padx=(0, 3), pady=5, sticky="ew")

        # --- Re-add the System Button ---
        system_button = ctk.CTkButton(
            master=theme_button_frame,  # <<<<<< Set master to the FRAME
            text="System",
            height=30,
            command=lambda: ctk.set_appearance_mode("system"),
            corner_radius=6,  # Example styling
            # fg_color=("gray75", "gray25"), # Optional shared style
            # hover_color=("gray70", "gray30")
        )
        # Grid the system button in the second column OF THE FRAME
        system_button.grid(row=0, column=1, padx=(3, 0), pady=5, sticky="ew")

        # --- END OF Combined Theme Buttons Section ---

        # --- Status Area ---
        self.status_frame = ctk.CTkFrame(sidebar, height=100, fg_color=("gray90", "gray10"), corner_radius=5)
        # Pack status frame normally AFTER the theme section
        self.status_frame.pack(fill="x", padx=10, pady=10)
        self.status_frame.pack_propagate(False)

        status_title_frame = ctk.CTkFrame(self.status_frame, fg_color="transparent")
        status_title_frame.pack(fill="x", padx=10, pady=(5, 2))

        self.status_indicator = ctk.CTkFrame(status_title_frame, width=12, height=12, corner_radius=6, fg_color="gray")
        self.status_indicator.pack(side="left", padx=(0, 5), pady=2)

        ctk.CTkLabel(status_title_frame, text="Status", font=ctk.CTkFont(weight="bold")).pack(side="left")

        self.status_label = ctk.CTkLabel(self.status_frame, text="Initializing...", wraplength=190, anchor="nw",
                                         justify="left")
        self.status_label.pack(anchor="w", padx=10, pady=(0, 10), fill="x", expand=True)

        # --- Exit Button ---
        self.exit_button = ctk.CTkButton(
            master=sidebar,
            text="Exit Application",  # Keep text for accessibility
            image=self.icons.get("exit"),  # Get loaded icon
            compound="left",  # Place icon to the left of text
            command=self.root.destroy,
            fg_color="#e74c3c",  # Changed back to red as requested before
            hover_color="#c0392b",
            text_color="#ffffff",
            height=40,
            corner_radius=8,
            border_width=1, # Optional border
            border_color="#c0392b",
            font=ctk.CTkFont(size=14, weight="bold")
        )
        self.exit_button.pack(side="bottom", fill="x", padx=10, pady=(15, 10))  # Added more top padding

    def _load_icons(self):
        """Loads icons using tkinter.PhotoImage."""
        if not os.path.isdir(ICON_DIR):
             print(f"Warning: Icon directory not found at {ICON_DIR}. Skipping icon loading.")
             self.icons = {}
             return

        # Define icon filenames (use .gif preferably, or .png if supported)
        icon_files = {
            "open": "open",
            "clear": "trash",
            "generate": "key",
            "process": "process",
            "save": "save",
            "exit": "exit",
            "sun": "sun",    # <-- Add sun
            "moon": "moon"   # <-- Add moon
            # Add more names and filenames as needed
        }
        self.icons = {}

        for name, base_filename in icon_files.items():

            try:
                # --- THIS IS THE KEY PART ---
                # It expects specific filenames based on the base_filename
                light_path = os.path.join(ICON_DIR, f"{base_filename}_light.png")
                dark_path = os.path.join(ICON_DIR, f"{base_filename}_dark.png")
                # ---------------------------

                if os.path.exists(light_path) and os.path.exists(dark_path):
                    # --- Creates CTkImage with BOTH light and dark versions ---
                    self.icons[name] = ctk.CTkImage(
                        light_image=Image.open(light_path),
                        dark_image=Image.open(dark_path),
                        size=(20, 20)
                    )
                    # -------------------------------------------------------
                else:
                    print(
                        f"Warning: Missing light or dark icon pair for '{base_filename}'. Icon '{name}' will be None.")
                    self.icons[name] = None
            except Exception as e:
                print(f"Error loading icon '{base_filename}': {e}")
                self.icons[name] = None

    def _toggle_appearance_mode(self):
        """Toggles between light and dark mode and updates the button."""
        current_mode = ctk.get_appearance_mode()  # Returns "Light" or "Dark"

        if current_mode == "Light":
            new_mode = "Dark"
            # Set button to show info for switching TO light next time
            button_text = " Light Mode"  # Add space for icon
            button_icon = self.icons.get("sun")
        else:
            new_mode = "Light"
            # Set button to show info for switching TO dark next time
            button_text = " Dark Mode"  # Add space for icon
            button_icon = self.icons.get("moon")

        # Apply the new appearance mode
        ctk.set_appearance_mode(new_mode)

        # Update the toggle button itself (if it exists)
        if self.theme_toggle_button:
            self.theme_toggle_button.configure(text=button_text, image=button_icon)

    def _validate_inputs_for_processing(self):
        """Checks if conditions are met to enable the Process button."""
        # Check if input textbox exists and has content
        if not self.input_textbox or not self.input_textbox.get("1.0", "end-1c"):
            return False  # No input text

        # Check if algorithm requires a key
        algorithm = self.algorithm_var.get()
        requires_key = self.methods.get(algorithm, False)

        if requires_key:
            # Check if key entry exists and has content
            if not self.key_entry or not self.key_entry.get():
                return False  # Key required but missing

            # Optional: Add basic format checks here later if desired
            # e.g., for Caesar: try int(self.key_entry.get()) except ValueError: return False
            # e.g., for OTP: try bytes.fromhex(self.key_entry.get()) except ValueError: return False
            # For now, just checking if *something* is entered is a good start.

        # If we reach here, all conditions are met
        return True

    # --- 2. Add Button State Update Method ---
    def _update_process_button_state(self):
        """Enables or disables the Process button based on input validity."""
        if self.is_processing:  # Don't change state if already processing
            return

        if self.process_button:  # Check if button exists
            if self._validate_inputs_for_processing():
                self.process_button.configure(state="normal")
            else:
                self.process_button.configure(state="disabled")


    def create_main_area(self):
        main_frame = ctk.CTkFrame(self.root, fg_color="transparent")
        main_frame.grid(row=0, column=1, rowspan=1, sticky="nsew", padx=20, pady=20)
        main_frame.grid_rowconfigure(0, weight=1)
        main_frame.grid_rowconfigure(2, weight=1)
        main_frame.grid_columnconfigure(0, weight=1)

        top_frame = ctk.CTkFrame(main_frame)
        top_frame.grid(row=0, column=0, sticky="nsew", pady=(0, 10))
        top_frame.grid_rowconfigure(1, weight=1)
        top_frame.grid_columnconfigure(0, weight=1)

        input_label_frame = ctk.CTkFrame(top_frame, fg_color="transparent")
        input_label_frame.grid(row=0, column=0, sticky="ew", pady=(5, 5), padx=10)
        input_label_frame.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(input_label_frame, text="Input Text / Source File", font=ctk.CTkFont(size=14, weight="bold")).grid(
            row=0, column=0, sticky="w")
        btn_frame_input = ctk.CTkFrame(input_label_frame, fg_color="transparent")
        btn_frame_input.grid(row=0, column=1, sticky="e")

        ctk.CTkButton(
            btn_frame_input, text="Open File", width=110, height=30,
            image=self.icons.get("open"), compound="left",  # Use PhotoImage
            command=self.open_file
        ).pack(side="left", padx=5)

        ctk.CTkButton(
            btn_frame_input, text="Clear Input", width=110, height=30,
            image=self.icons.get("clear"), compound="left",  # Use PhotoImage
            fg_color="gray50", hover_color="gray40",
            command=self.clear_input
        ).pack(side="left", padx=(0, 5))

        # ctk.CTkButton(btn_frame_input, text="Open File", width=100, height=30, command=self.open_file).pack(side="left",
        #                                                                                                     padx=5)
        # ctk.CTkButton(btn_frame_input, text="Clear Input", width=100, height=30, fg_color="gray50",
        #               hover_color="gray40", command=self.clear_input).pack(side="left", padx=(0, 5))

        self.input_textbox = ctk.CTkTextbox(top_frame, font=ctk.CTkFont(family="Consolas", size=13), wrap="word")
        self.input_textbox.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))

        if self.input_textbox:
            self.input_textbox.bind("<KeyRelease>", lambda event: self._update_process_button_state(), add='+')

            # Update button state when text changes in key entry
        if self.key_entry:
            self.key_entry.bind("<KeyRelease>", lambda event: self._update_process_button_state(), add='+')

        middle_frame = ctk.CTkFrame(main_frame)
        middle_frame.grid(row=1, column=0, sticky="ew", pady=10, ipady=5)
        middle_frame.grid_columnconfigure(1, weight=1)

        self.generate_key_button = ctk.CTkButton(
            middle_frame, text="Generate Key", width=130,
            image=self.icons.get("generate"), compound="left",  # Use PhotoImage
            command=self.generate_key, fg_color="#27ae60", hover_color="#2ecc71")
        self.generate_key_button.grid(row=0, column=2, padx=(5, 10), pady=10)

        key_label = ctk.CTkLabel(middle_frame, text="Secret Key:")
        key_label.grid(row=0, column=0, padx=(15, 5), pady=10, sticky="w")

        self.key_entry = ctk.CTkEntry(middle_frame)
        self.key_entry.grid(row=0, column=1, sticky="ew", padx=0, pady=10)

        self.process_button = ctk.CTkButton(
            middle_frame, text="Process", width=110,
            image=self.icons.get("process"), compound="left",  # Use PhotoImage
            command=self.process_text_threaded, font=ctk.CTkFont(weight="bold"))
        self.process_button.grid(row=0, column=3, padx=(0, 15), pady=10)


        # self.generate_key_button = ctk.CTkButton(
        #     middle_frame, text="Generate Key", width=120, command=self.generate_key,
        #     fg_color="#27ae60", hover_color="#2ecc71")
        # self.generate_key_button.grid(row=0, column=2, padx=(5, 10), pady=10)

        # self.process_button = ctk.CTkButton(
        #     middle_frame, text="Process", width=120, command=self.process_text_threaded,
        #     font=ctk.CTkFont(weight="bold"))
        # self.process_button.grid(row=0, column=3, padx=(0, 15), pady=10)

        self.bottom_frame = ctk.CTkFrame(main_frame)
        self.bottom_frame.grid(row=2, column=0, sticky="nsew", pady=(10, 0))
        self.bottom_frame.grid_rowconfigure(1, weight=1)
        self.bottom_frame.grid_columnconfigure(0, weight=1)
        output_label_frame = ctk.CTkFrame(self.bottom_frame, fg_color="transparent")
        output_label_frame.grid(row=0, column=0, sticky="ew", pady=(5, 5), padx=10)
        output_label_frame.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(output_label_frame, text="Output Text / Result File",
                     font=ctk.CTkFont(size=14, weight="bold")).grid(row=0, column=0, sticky="w")


        # self.save_button = ctk.CTkButton(
        #     output_label_frame, text="Save Output", width=120, command=self.save_output,
        #     fg_color="#e74c3c", hover_color="#c0392b", state="disabled")
        # self.save_button.grid(row=0, column=1, sticky="e", padx=(0, 5))

        self.save_button = ctk.CTkButton(
            output_label_frame, text="Save Output", width=130,
            image=self.icons.get("save"), compound="left",  # Use PhotoImage
            command=self.save_output, fg_color="#e74c3c", hover_color="#c0392b", state="disabled")
        self.save_button.grid(row=0, column=1, sticky="e", padx=(0, 5))

        self.output_textbox = ctk.CTkTextbox(self.bottom_frame, font=ctk.CTkFont(family="Consolas", size=13),
                                             wrap="word", state="disabled")
        self.output_textbox.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))

    def select_method(self, method):
        if self.is_processing:
            return

        selected_method = self.algorithm_var.get()

        if selected_method == method:
            return

        self.algorithm_var.set(method)
        for btn_name, btn_widget in self.sidebar_buttons.items():
            if btn_widget:
                btn_widget.configure(fg_color=("gray75", "gray25") if btn_name == method else "transparent")
        self.update_key_entry_state()
        self._update_process_button_state()

    def update_key_entry_state(self):
        method = self.algorithm_var.get()
        requires_key = self.methods.get(method, False)
        key_state = "normal" if requires_key else "disabled"

        # --- Define placeholder text based on method ---
        placeholder = ""
        if requires_key:
            if method == "Caesar":
                placeholder = "Enter integer shift (e.g., 3)"
            elif method == "Rail Fence":
                placeholder = "Enter number of rails (e.g., 4)"
            elif method == "Playfair":
                placeholder = "Enter keyword (letters only)"
            elif method == "Transposition":
                placeholder = "Enter keyword"
            elif method == "Substitution":
                placeholder = "Enter 26-letter alphabet permutation"
            elif method == "OTP":
                placeholder = "Enter Hex key (same byte length as input)"
            else:
                placeholder = "Enter required key"  # Generic fallback
        # ------------------------------------------------

        if self.key_entry:
            self.key_entry.configure(state=key_state, placeholder_text=placeholder)  # Set placeholder
            if not requires_key:
                self.key_entry.delete(0, "end")

        if self.generate_key_button:
            self.generate_key_button.configure(state=key_state)

        status_msg = f"Selected: {method}. {'Key required.' if requires_key else 'No key needed.'}"
        status_color = "gray" if not self.is_processing else "yellow"
        self.update_status(status_msg, status_color)
        self._update_process_button_state()  # <-- ADD THIS CALL

    def update_ui_for_operation(self):
        if self.is_processing:
            return
        op = self.operation_var.get()
        if self.process_button:
            self.process_button.configure(text=f"{op.capitalize()}")
        if not self.is_processing:
            self.update_status(f"Mode set to: {op.capitalize()}", "gray")

    def open_file(self):
        if self.is_processing:
            return
        filepath = tkinter.filedialog.askopenfilename(
            title="Open Text File",
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
        if not filepath or not self.input_textbox:
            return
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
            self.input_textbox.delete("1.0", "end")
            self.input_textbox.insert("1.0", content)
            self.current_input_file = filepath
            self.update_status(f"Opened: {os.path.basename(filepath)}", "green")
            if self.output_textbox:
                self.output_textbox.configure(state="normal")
                self.output_textbox.delete("1.0", "end")
                self.output_textbox.configure(state="disabled")
            if self.save_button:
                self.save_button.configure(state="disabled")

            self._update_process_button_state()
        except Exception as e:
            try:
                with open(filepath, 'r') as f:
                    content = f.read()
                self.input_textbox.delete("1.0", "end")
                self.input_textbox.insert("1.0", content)
                self.current_input_file = filepath
                self.update_status(f"Opened: {os.path.basename(filepath)} (used default encoding)", "green")
                if self.output_textbox:
                    self.output_textbox.configure(state="normal")
                    self.output_textbox.delete("1.0", "end")
                    self.output_textbox.configure(state="disabled")
                if self.save_button:
                    self.save_button.configure(state="disabled")

                self._update_process_button_state()
            except Exception as e2:
                self.update_status(f"Error opening file: {e2}", "red")
                tkinter.messagebox.showerror("File Error", f"Could not read file:\n{e}\n{e2}")
                self._update_process_button_state()

    def clear_input(self):
        if self.is_processing:
            return
        if self.input_textbox:
            self.input_textbox.delete("1.0", "end")
        if self.output_textbox:
            self.output_textbox.configure(state="normal")
            self.output_textbox.delete("1.0", "end")
            self.output_textbox.configure(state="disabled")
        self.current_input_file = None
        if self.save_button:
            self.save_button.configure(state="disabled")
        self.update_status("Input cleared", "gray")
        self._update_process_button_state()

    def generate_key(self):
        if self.is_processing or not self.key_entry:
            return
        method = self.algorithm_var.get()
        if not self.methods.get(method, False):
            self.update_status(f"{method} does not require a key.", "orange")
            return
        text_byte_len = 0
        if method == "OTP":
            if not self.input_textbox:
                return
            current_input = self.input_textbox.get("1.0", "end-1c")
            if not current_input:
                self.update_status("Enter input text before generating OTP key.", "orange")
                self.pulse_widget(self.input_textbox, "#FFA500")
                return
            try:
                text_byte_len = len(current_input.encode('utf-8'))
            except Exception as enc_err:
                self.update_status(f"Input encoding error: {enc_err}", "red")
                return
        try:
            generated_key = generate_appropriate_key(method, text_byte_length=text_byte_len)
            self.key_entry.delete(0, "end")
            self.key_entry.insert(0, generated_key)

            self.key_entry.select_range(0, 'end')  # Select the entire text
            self.key_entry.focus()  # Optional: give focus back to the key entry

            self.update_status(f"{method} key generated.", "green")
            if self.generate_key_button:
                self.pulse_button(self.generate_key_button)

            self._update_process_button_state()

        except ValueError as ve:
            self.update_status(f"Key generation error: {ve}", "red")
            self._update_process_button_state()
        except Exception as e:
            self.update_status(f"Unexpected key gen error: {e}", "red")
            self._update_process_button_state()

    def save_output(self):
        if self.is_processing or not self.output_textbox:
            return
        self.output_textbox.configure(state="normal")
        output_text = self.output_textbox.get("1.0", "end-1c")
        self.output_textbox.configure(state="disabled")
        if not output_text:
            self.update_status("Nothing to save.", "orange")
            self.pulse_widget(self.output_textbox, "#FFA500")
            return

        op = self.operation_var.get()
        algo = self.algorithm_var.get().lower()
        default_ext = ".txt"
        file_types = [("Text Files", "*.txt"), ("All Files", "*.*")]
        is_likely_binary = False

        if op == 'encrypt':
            default_ext = f".{algo}.enc"
            file_types = [(f"{algo.upper()} Encrypted", f"*{default_ext}"), ("Encrypted Data", "*.enc"),
                          ("All Files", "*.*")]
            if algo == 'otp':
                try:
                    bytes.fromhex(output_text)
                    default_ext = ".hex.enc"
                    file_types.insert(1, ("Hex Encoded", "*.hex *.hex.enc"))
                    is_likely_binary = True
                except ValueError:
                    default_ext = ".txt.enc"
                    file_types.insert(0, ("Text Encrypted", "*.txt.enc"))
        elif op == 'decrypt':
            if algo == 'otp' and all(c in string.hexdigits for c in output_text):
                try:
                    bytes.fromhex(output_text)
                    default_ext = ".bin"
                    file_types = [("Binary Data", "*.bin"), ("All Files", "*.*")]
                    is_likely_binary = True
                except ValueError:
                    pass

        default_name = ""
        if self.current_input_file:
            base, _ = os.path.splitext(os.path.basename(self.current_input_file))
            if op == 'decrypt':
                known_enc_suffixes = [f".{a}.enc" for a in self.methods] + [".enc", ".hex.enc", ".txt.enc"]
                for suffix in known_enc_suffixes:
                    if base.endswith(suffix):
                        base = base[:-len(suffix)]
                        break
            default_name = f"{base}_{op}{default_ext}"
        else:
            default_name = f"output_{op}{default_ext}"

        filepath = tkinter.filedialog.asksaveasfilename(
            title="Save Output File",
            initialfile=default_name,
            defaultextension=default_ext,
            filetypes=file_types)

        if not filepath:
            return

        try:
            mode = 'wb' if is_likely_binary else 'w'
            encoding = None if mode == 'wb' else 'utf-8'
            data_to_write = output_text

            if mode == 'wb':
                if isinstance(output_text, str):
                    try:
                        data_to_write = bytes.fromhex(output_text)
                    except ValueError:
                        mode, encoding, data_to_write = 'w', 'utf-8', output_text
                elif not isinstance(output_text, bytes):
                    mode, encoding, data_to_write = 'w', 'utf-8', str(output_text)

            with open(filepath, mode, encoding=encoding) as f:
                f.write(data_to_write)

            self.update_status(f"Output saved to: {os.path.basename(filepath)}", "green")
            if self.save_button:
                self.pulse_button(self.save_button)
        except Exception as e:
            self.update_status(f"Error saving file: {e}", "red")
            tkinter.messagebox.showerror("File Error", f"Could not save file:\n{e}")

    def process_text_threaded(self):
        if self.is_processing:
            self.update_status("Processing already in progress...", "orange")
            return

        if not self.input_textbox or not self.key_entry:
            self.update_status("UI components not ready.", "red")
            return

        input_text = self.input_textbox.get("1.0", "end-1c")
        key = self.key_entry.get()
        algorithm = self.algorithm_var.get()
        operation = self.operation_var.get()

        if not input_text:
            self.update_status("Input text is empty.", "orange")
            self.pulse_widget(self.input_textbox, "#FFA500")
            return

        if self.methods.get(algorithm, False) and not key:
            self.update_status(f"{algorithm} requires a key.", "orange")
            self.pulse_widget(self.key_entry, "#FFA500")
            return

        if algorithm == 'OTP':
            try:
                bytes.fromhex(key)
            except ValueError:
                self.update_status("OTP key must be a valid Hex string.", "red")
                self.pulse_widget(self.key_entry, "#E74C3C")
                return

            if operation == 'decrypt':
                try:
                    bytes.fromhex(input_text)
                except ValueError:
                    self.update_status("Warning: OTP key is Hex, but input text is not.", "orange")

        self.is_processing = True
        self.set_ui_processing(True)
        self.update_status(f"Processing ({operation}ion with {algorithm})...", "yellow")
        thread = threading.Thread(target=self.run_encryption_logic, args=(algorithm, operation, input_text, key),
                                  daemon=True)
        thread.start()

    def run_encryption_logic(self, algorithm, operation, text, key):
        logic = EncryptionLogic()
        start_time = time.time()
        result = None
        error_message = None
        is_hex_output = False

        try:
            encrypt_mode = (operation == 'encrypt')
            if algorithm == "OTP":
                result = logic.otp_cipher(text, key, encrypt_mode)
            elif algorithm == "Caesar":
                result = logic.caesar_cipher(text, key, encrypt_mode)
            elif algorithm == "ROT13":
                result = logic.rot13_cipher(text)
            elif algorithm == "Playfair":
                result = logic.playfair_cipher(text, key, encrypt_mode)
            elif algorithm == "Transposition":
                result = logic.transposition_cipher(text, key, encrypt_mode)
            elif algorithm == "Substitution":
                result = logic.substitution_cipher(text, key, encrypt_mode)
            elif algorithm == "Rail Fence":
                result = logic.rail_fence_cipher(text, key, encrypt_mode)
            else:
                raise NotImplementedError(f"Algorithm '{algorithm}' not implemented.")

            if algorithm == "OTP" and encrypt_mode and isinstance(result, str):
                try:
                    bytes.fromhex(result)
                    is_hex_output = True
                except ValueError:
                    pass
        except ValueError as ve:
            error_message = f"Error: {ve}"
        except Exception as e:
            error_message = f"Unexpected error: {e}"
            import traceback
            traceback.print_exc()

        duration = time.time() - start_time
        self.root.after(0, self.processing_complete, result, error_message, operation, algorithm, duration,
                        is_hex_output)

    def processing_complete(self, result_data, error_message, operation, algorithm, duration, is_hex_output=False):
        display_text = ""
        config_options = {"state": "normal"}

        if error_message:
            self.update_status(error_message, "red")
            display_text = f"ERROR:\n{error_message}"
            config_options["text_color"] = ("#C0392B", "#E74C3C")
            if self.save_button:
                self.save_button.configure(state="disabled")
            if self.status_frame:
                self.pulse_widget(self.status_frame, "#E74C3C")
        elif result_data is not None:
            display_text = str(result_data)
            status_msg = f"{operation.capitalize()}ion complete ({algorithm}) in {duration:.3f}s."
            if is_hex_output:
                status_msg += " (Output is Hex)"
            self.update_status(status_msg, "green")
            if self.save_button:
                self.save_button.configure(state="normal")
            if self.bottom_frame:
                self.pulse_widget(self.bottom_frame, "#2ECC71")
        else:
            display_text = "Processing finished with no result."
            self.update_status(display_text, "orange")
            if self.save_button:
                self.save_button.configure(state="disabled")

        if self.output_textbox:
            self.output_textbox.configure(**config_options)
            self.output_textbox.delete("1.0", "end")
            self.output_textbox.insert("1.0", display_text)
            self.output_textbox.configure(state="disabled")

        self.is_processing = False
        self.set_ui_processing(False)

    def set_ui_processing(self, processing):
        """Enable/disable relevant UI elements during processing."""
        state = "disabled" if processing else "normal"

        # --- Modify Process button handling ---
        if self.process_button:
            if processing:
                self.process_button.configure(state="disabled")  # Always disable when processing
            else:
                # When processing stops, re-validate inputs to set correct state
                self._update_process_button_state()
        # ------------------------------------

        method = self.algorithm_var.get()
        key_required = self.methods.get(method, False)

        if self.generate_key_button:
            self.generate_key_button.configure(state="disabled" if processing or not key_required else "normal")

        if self.key_entry:
            self.key_entry.configure(state="disabled" if processing or not key_required else "normal")

        if self.save_button:
            current_save_state = self.save_button.cget('state')
            self.save_button.configure(state="disabled" if processing or current_save_state == 'disabled' else "normal")

        for btn in self.sidebar_buttons.values():
            if btn:
                btn.configure(state=state)

        if self.operation_frame:
            for radio in self.operation_frame.winfo_children():
                if isinstance(radio, ctk.CTkRadioButton):
                    radio.configure(state=state)

        if self.input_textbox:
            self.input_textbox.configure(state=state)

        if self.exit_button:
            self.exit_button.configure(state=state)

        if self.status_indicator:
            if processing:
                self.status_indicator.configure(fg_color=("#f39c12", "#f1c40f"))

        self.root.config(cursor="watch" if processing else "")

    def update_status(self, text, color_name="gray"):
        if not self.status_label:
            return

        self.status_label.configure(text=text)

        if self.status_indicator and (not self.is_processing or color_name in ["red", "green", "orange"]):
            color_map = {
                "gray": ("gray50", "gray50"),
                "green": ("#27ae60", "#2ecc71"),
                "red": ("#c0392b", "#e74c3c"),
                "orange": ("#f39c12", "#f1c40f"),
                "yellow": ("#f39c12", "#f1c40f")
            }
            fg_color = color_map.get(color_name, color_map["gray"])
            self.status_indicator.configure(fg_color=fg_color)

    def pulse_widget(self, widget, highlight_color="#3498db"):
        if not widget or not hasattr(widget, 'configure') or not hasattr(widget, 'cget'):
            return

        original_color = None
        prop_to_change = None

        try:
            if isinstance(widget, (ctk.CTkTextbox, ctk.CTkEntry)):
                prop_to_change = "border_color"
            else:
                prop_to_change = "fg_color"

            if prop_to_change:
                original_color = widget.cget(prop_to_change)
                widget.configure(**{prop_to_change: highlight_color})
                if original_color is not None:
                    self.root.after(300, lambda: widget.configure(**{prop_to_change: original_color}))
        except Exception as e:
            print(f"Widget pulse error: {e}")

    def pulse_button(self, button):
        if not button or not hasattr(button, 'configure') or not hasattr(button, 'cget'):
            return

        try:
            original_color = button.cget("fg_color")
            highlight_color = button.cget("hover_color")
            if highlight_color is not None and original_color is not None:
                button.configure(fg_color=highlight_color)
                self.root.after(200, lambda b=button, oc=original_color: b.configure(fg_color=oc))
        except Exception as e:
            print(f"Button pulse error: {e}")


    def run(self):
        self.root.mainloop()