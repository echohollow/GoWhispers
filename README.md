# GoWhispers

## Windows Syscall Stub Generator for Security Professionals

GoWhispers is an advanced tool designed for security researchers, system programmers, and malware analysts who need to work with Windows syscalls directly. It generates clean, reliable syscall stubs for various applications while avoiding common detection mechanisms.

## Features

- **Syscall Generation**: Create direct syscall stubs in multiple formats (Go, C, Hex, Binary)
- **Architecture Support**: Generate stubs for both x64 and x86 architectures
- **Encryption Options**: Secure your stubs with AES-256 GCM or XOR encryption
- **Custom Syscalls**: Easily add your own custom syscalls with their IDs
- **Professional UI**: Clean, modern interface with detailed activity logging
- **Variable Naming**: Customize variable names for generated code
- **UTF-8 Support**: Proper encoding handling for all file operations

## Screenshots

![GoWhispers Screenshot](https://github.com/user-attachments/assets/9c809ec0-8ad6-46a5-a409-735ec403eaf9)


## Installation

### Prerequisites

- Python 3.8 or higher
- Required Python packages:
  - pycryptodome
  - pillow (PIL)
  - tkinter (usually comes with Python)

### Setup

1. Clone this repository:
   ```
   git clone https://github.com/echohollow/GoWhispers.git
   cd gowhispers
   ```

2. Install required packages:
   ```
   pip install pycryptodome pillow
   ```

3. Run the application:
   ```
   python gui.py
   ```

## Usage

1. **Select syscalls** from the dropdown or add custom ones
2. **Choose your output format** (Go, C, Hex, or Binary)
3. **Select encryption method** if desired
4. **Specify a variable name** for generated code (optional)
5. **Click "Generate Stub"** to create and save your stub

### Supported Formats

- **go**: Go language source code
- **c**: C language source code
- **hex**: Hexadecimal text representation
- **bin**: Raw binary output
- **raw**: Raw text output

### Encryption Options

- **none**: No encryption
- **aes**: AES-256 GCM mode encryption (requires key)
- **xor**: SHA-256 based XOR encryption (requires key)

## Adding Custom Syscalls

You can add custom syscalls by:

1. Entering the syscall name (must start with "Nt" followed by a capital letter)
2. Providing the syscall ID in hexadecimal format
3. Clicking "Add Custom"

Added syscalls remain available in the dropdown for the duration of the session.

## Technical Details

GoWhispers generates stubs that work through direct syscall invocation, bypassing common API hooking techniques. The stubs are generated as:

- **x64**: Using the `syscall` instruction
- **x86**: Using the legacy `call dword ptr [0x7FFE0300]` method

## Project Structure

- **gui.py**: Main application interface
- **sysgen.py**: Syscall stub generation module
- **encryptor.py**: Encryption and decryption functions
- **outputter.py**: File output and format conversion

## Security Notice

This tool is intended for legitimate security research, system programming, and educational purposes only. Please use responsibly and in accordance with applicable laws and regulations.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contact

For questions, suggestions, or collaboration, please reach out to [echohollow@tutamail.com].

## Acknowledgments

- Thanks to the security research community for their valuable work on Windows syscall mechanisms
- Special appreciation to all contributors and testers who helped improve this tool
