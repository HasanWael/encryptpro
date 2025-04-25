# EncryptPro - Encryption/Decryption Tool

A modern graphical user interface (GUI) application built with CustomTkinter for encrypting and decrypting text or files using various classical cryptography algorithms.

## Description

EncryptPro provides an easy-to-use interface for exploring common encryption techniques. It allows users to select an algorithm, enter text or open a file, provide a key (if required), and perform encryption or decryption. The application features a clean, modern look with light/dark/system theme support.

**Disclaimer:** The ciphers implemented here (except potentially OTP under strict conditions) are **classical ciphers and are NOT considered secure** for protecting sensitive information against modern cryptanalysis. This tool is primarily for educational and demonstrational purposes.

## Features

*   **Algorithms Supported:**
    *   One-Time Pad (OTP) - XOR-based
    *   Caesar Cipher
    *   ROT13
    *   Playfair Cipher
    *   Columnar Transposition
    *   Simple Monoalphabetic Substitution
    *   Rail Fence Cipher
*   **Operations:** Encrypt / Decrypt mode selection.
*   **Input:** Manual text entry or opening text files (`.txt`).
*   **Output:** Display results in the GUI or save to a file.
*   **Key Management:** Input field for required keys and a basic "Generate Key" function suggesting appropriate key formats.
*   **GUI:**
    *   Built with CustomTkinter for a modern look and feel.
    *   Responsive elements (buttons enable/disable based on input validity).
    *   Status bar with informative messages and status indicators.
    *   Icons for primary action buttons (requires Pillow).
    *   Theme switching: Includes a Light/Dark mode toggle button and an explicit System mode button.
*   **Structure:** Modularized code (GUI, logic, utils separated).

## Screenshot
```
![EncryptPro Screenshot]](https://ibb.co/4gC9V2XX)
```

## Requirements

*   Python 3.8 or higher
*   `pip` (Python package installer)
*   External Libraries (see `requirements.txt`):
    *   `customtkinter`
    *   `Pillow` (for icon display)

## Installation

1.  **Clone or Download:** Get the project files onto your local machine.
    ```bash
    git clone https://github.com/HasanWael/encryptpro.git # Or download ZIP and extract
    cd encryptpro_project
    ```
2.  **Create a Virtual Environment (Recommended):**
    ```bash
    python -m venv .venv
    ```
3.  **Activate the Virtual Environment:**
    *   **Windows (cmd/powershell):**
        ```cmd
        .\.venv\Scripts\activate
        ```
    *   **macOS/Linux (bash/zsh):**
        ```bash
        source .venv/bin/activate
        ```
4.  **Install Dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

## Usage

Ensure your virtual environment is activated. Run the application from the root project directory (`encryptpro_project/`):

```bash
python -m encryptpro.main
```
or
```bash
python encryptpro/main.py
```

The application window will appear.

1.  Select an encryption/decryption algorithm from the sidebar.
2.  Choose the operation mode (Encrypt/Decrypt).
3.  Enter text directly into the "Input Text" box or use "Open File" to load from a `.txt` file.
4.  If the selected algorithm requires a key, enter it in the "Secret Key" field or use "Generate Key". Pay attention to the placeholder text for the expected format.
5.  Click the "Process" button (it will be enabled only when required inputs are present).
6.  View the result in the "Output Text" box.
7.  Use "Save Output" to save the result to a file.
8.  Use the theme buttons in the sidebar to change the appearance.
9.  Click the "Exit Application" button in the sidebar to close the program.

## Project Structure

```
encryptpro_project/
├── encryptpro/            # Main Python package
│   ├── icons/             # Directory for icon images (.png)
│   │   ├── folder_light.png
│   │   ├── folder_dark.png
│   │   ├── trash_light.png
│   │   ├── ... (other paired icons)
│   │   ├── sun.png        # Single icon for theme toggle
│   │   └── moon.png       # Single icon for theme toggle
│   ├── __init__.py      # Package marker
│   ├── gui.py           # User Interface code (ModernEncryptionApp class)
│   ├── logic.py         # Encryption algorithm logic (EncryptionLogic class)
│   ├── utils.py         # Utility functions (e.g., key generation)
│   └── main.py          # Application entry point
│
├── requirements.txt       # Project dependencies
└── README.md              # This file
```

## Disclaimer

This application implements classical cryptography algorithms which are **insecure for modern use cases**. Do not use this tool to protect sensitive data. The One-Time Pad (OTP) implementation is theoretically secure *only if* the key is truly random, used only once, kept secret, and is at least as long as the message; proper key management is critical and complex. This project is for educational purposes only.

## License

This project is licensed under the MIT License.
