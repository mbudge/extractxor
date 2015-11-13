# extractxor
Extract obfuscated executables from files.

Usage:

Single File: python extractxor.py -f image.jpeg

Directory Scan: python extractxor.py -d c:\folder_name

Verbose: python extractxor.py -f image.jpeg -v

Directory Scan + Max Filesize: python extractxor.py -d c:\folder_name -s 1024

-Max filesize in bytes applies to directory scan only.


test_extractxor.py Usage:

python test_extractxor.py

First edit the file before running the script.

XOR_KEY = 1 - Set the xor key to a value between 1 and 256.
IMAGE_FILE = 'FILENAME.jpg' - Set the image filename or filepath.
EXECUTABLE_FILE = 'FILENAME.exe' - Set the executable filename or filepath.

The output file is called 'image_with_exe.jpg'
