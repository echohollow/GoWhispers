import binascii
import os
import logging
import time
from typing import Union, Optional, Dict, Any, List
import hashlib

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("outputter")

class OutputError(Exception):
    """Custom exception for output-related errors"""
    pass

# Supported output formats
OUTPUT_FORMATS = {
    'go': 'Go language source code',
    'c': 'C language source code', 
    'bin': 'Raw binary data',
    'hex': 'C-style hex array',
    'raw': 'Raw text'
}

def save_stub(data: Union[bytes, str], fmt: str, out_path: str, 
             chunk_size: int = 4096, max_size: int = 10*1024*1024,
             var_name: Optional[str] = None) -> Dict[str, Any]:
    """
    Save stub data in various formats with validation and metadata.
    
    Args:
        data: Data to save (bytes or string)
        fmt: Output format ('go', 'c', 'bin', 'hex', 'raw')
        out_path: Output file path
        chunk_size: Write chunk size in bytes
        max_size: Maximum allowed file size
        var_name: Optional variable name for array/slice formats
    
    Returns:
        Dictionary containing metadata about the saved file
    
    Raises:
        OutputError: If saving fails
        ValueError: For invalid parameters
    """
    # Input validation
    if not data:
        logger.error("No data provided to save")
        raise OutputError("No data provided to save")
    
    if not isinstance(data, (bytes, str)):
        logger.error(f"Invalid data type: {type(data).__name__}")
        raise ValueError(f"Data must be bytes or string, not {type(data).__name__}")
    
    fmt = fmt.lower()
    if fmt not in OUTPUT_FORMATS:
        logger.error(f"Unsupported format: {fmt}")
        supported = ', '.join(OUTPUT_FORMATS.keys())
        raise ValueError(f"Unsupported format: {fmt}. Valid formats are: {supported}")
    
    if len(data) > max_size:
        logger.error(f"Data too large: {len(data)} bytes (max: {max_size})")
        raise OutputError(f"Data too large (>{max_size} bytes)")
    
    logger.info(f"Saving {len(data)} bytes as {fmt} format to {out_path}")
    start_time = time.time()

    try:
        # Convert data based on the output format
        if fmt == 'hex' and isinstance(data, bytes):
            output_data = convert_to_hex_array(data, var_name=var_name)
            logger.debug("Converted data to hex array")
        elif fmt == 'go' and isinstance(data, bytes):
            output_data = convert_to_go_byte_slice(data, var_name=var_name)
            logger.debug("Converted data to Go byte slice")
        elif fmt in ('go', 'c') and isinstance(data, bytes):
            # For direct text output of code (not byte arrays)
            output_data = data.decode('utf-8', errors='replace')
            logger.debug("Decoded binary data to UTF-8 text")
        else:
            output_data = data

        # Create directory if it doesn't exist
        directory = os.path.dirname(out_path)
        if directory:
            os.makedirs(directory, exist_ok=True)
            logger.debug(f"Ensured directory exists: {directory}")

        # Write file with proper encoding
        write_mode = 'wb' if isinstance(output_data, bytes) else 'w'
        encoding = 'utf-8' if write_mode == 'w' else None
        
        with open(out_path, write_mode, encoding=encoding) as f:
            if isinstance(output_data, str):
                f.write(output_data)
            else:
                # Write in chunks to handle large files
                for i in range(0, len(output_data), chunk_size):
                    f.write(output_data[i:i+chunk_size])
        
        logger.debug(f"File written successfully in {time.time() - start_time:.2f} seconds")

        # Generate metadata for the saved file
        file_info = collect_file_metadata(data, out_path, fmt)
        logger.info(f"File saved: {file_info['file_path']} ({file_info['size']} bytes)")
        
        return file_info

    except PermissionError as e:
        logger.error(f"Permission denied: {out_path}")
        raise OutputError(f"Permission denied: {out_path}")
    except OSError as e:
        logger.error(f"File system error: {str(e)}")
        raise OutputError(f"File system error: {str(e)}")
    except UnicodeEncodeError as e:
        logger.error(f"Encoding error: {str(e)}")
        raise OutputError(f"Encoding error: {str(e)}. Try using a different format.")
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        raise OutputError(f"Unexpected error: {str(e)}")

def collect_file_metadata(data: Union[bytes, str], file_path: str, fmt: str) -> Dict[str, Any]:
    """
    Collect metadata about the saved file
    
    Args:
        data: Original data that was saved
        file_path: Path where the file was saved
        fmt: Format of the saved file
        
    Returns:
        Dictionary with file metadata
    """
    # Calculate file hash
    file_hash = hashlib.sha256()
    if isinstance(data, bytes):
        file_hash.update(data)
    else:
        file_hash.update(data.encode('utf-8'))
    
    # Get file stats
    try:
        file_stats = os.stat(file_path)
        file_size_on_disk = file_stats.st_size
        file_created = time.ctime(file_stats.st_ctime)
    except:
        file_size_on_disk = None
        file_created = None
    
    return {
        'file_path': os.path.abspath(file_path),
        'format': fmt,
        'size': len(data),
        'size_on_disk': file_size_on_disk,
        'sha256': file_hash.hexdigest(),
        'created': file_created,
        'original_type': 'bytes' if isinstance(data, bytes) else 'string'
    }

def convert_to_hex_array(data: bytes, bytes_per_line: int = 12, 
                        var_name: Optional[str] = None) -> str:
    """
    Convert bytes to formatted C-style hex array.
    
    Args:
        data: Bytes to convert
        bytes_per_line: Number of bytes per line
        var_name: Optional variable name for the array
    
    Returns:
        Formatted hex array as string
    """
    if not data:
        return ""
    
    if not var_name:
        var_name = "payload"
    
    hex_bytes = [f"0x{b:02x}" for b in data]
    array_lines = []
    
    for i in range(0, len(hex_bytes), bytes_per_line):
        line = "    " + ", ".join(hex_bytes[i:i+bytes_per_line])
        array_lines.append(line)

    output = f"// Generated hex array - {len(data)} bytes\n"
    output += f"unsigned char {var_name}[] = {{\n"
    output += ",\n".join(array_lines)
    output += "\n};\n"
    output += f"unsigned int {var_name}_size = {len(data)};\n"
    
    return output

def convert_to_go_byte_slice(data: bytes, bytes_per_line: int = 12,
                           var_name: Optional[str] = None) -> str:
    """
    Convert bytes to Go-style byte slice.
    
    Args:
        data: Bytes to convert
        bytes_per_line: Number of bytes per line
        var_name: Optional variable name for the slice
    
    Returns:
        Formatted byte slice as string
    """
    if not data:
        return ""
    
    if not var_name:
        var_name = "payload"
    
    hex_bytes = [f"0x{b:02x}" for b in data]
    array_lines = []
    
    for i in range(0, len(hex_bytes), bytes_per_line):
        line = "    " + ", ".join(hex_bytes[i:i+bytes_per_line])
        array_lines.append(line)

    output = f"// Generated byte slice - {len(data)} bytes\n"
    output += f"var {var_name} = []byte{{\n"
    output += ",\n".join(array_lines)
    output += "\n}\n"
    
    return output

def format_as_raw_string(data: bytes, encoding: str = 'utf-8',
                        errors: str = 'replace') -> str:
    """
    Convert bytes to raw string with encoding options.
    
    Args:
        data: Bytes to convert
        encoding: Target encoding
        errors: How to handle encoding errors
    
    Returns:
        Formatted string
    """
    try:
        return data.decode(encoding, errors=errors)
    except UnicodeDecodeError:
        logger.warning(f"Could not decode using {encoding}, falling back to hex representation")
        return data.hex()

def read_stub(file_path: str, as_bytes: bool = True) -> Union[bytes, str]:
    """
    Read stub data from a file.
    
    Args:
        file_path: Path to the file
        as_bytes: If True, return bytes; if False, return string
        
    Returns:
        File contents as bytes or string
        
    Raises:
        OutputError: If reading fails
    """
    if not os.path.exists(file_path):
        logger.error(f"File not found: {file_path}")
        raise OutputError(f"File not found: {file_path}")
    
    try:
        mode = 'rb' if as_bytes else 'r'
        encoding = None if as_bytes else 'utf-8'
        
        with open(file_path, mode, encoding=encoding) as f:
            content = f.read()
        
        logger.info(f"Read {len(content)} {'bytes' if as_bytes else 'characters'} from {file_path}")
        return content
        
    except Exception as e:
        logger.error(f"Error reading file: {str(e)}")
        raise OutputError(f"Error reading file: {str(e)}")

def detect_format(file_path: str) -> str:
    """
    Detect the format of a file based on its extension.
    
    Args:
        file_path: Path to the file
        
    Returns:
        Detected format ('go', 'c', 'bin', 'hex', or 'raw')
    """
    _, ext = os.path.splitext(file_path.lower())
    
    if ext == '.go':
        return 'go'
    elif ext in ('.c', '.h'):
        return 'c'
    elif ext in ('.bin', '.dat', '.syscall'):
        return 'bin'
    elif ext in ('.hex', '.txt'):
        return 'hex'
    else:
        return 'raw'

def get_output_formats() -> Dict[str, str]:
    """
    Get all supported output formats.
    
    Returns:
        Dictionary of format names and descriptions
    """
    return dict(OUTPUT_FORMATS)


# If this module is run directly, show a simple overview
if __name__ == "__main__":
    print("GoWhispers Output Formats")
    print("=======================")
    for fmt, desc in OUTPUT_FORMATS.items():
        print(f"- {fmt}: {desc}")