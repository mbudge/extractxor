from operator import xor

# Set the xor_key
# Set the image and executable filename or filepath
#The script xor's the executable and embeds it at the end of the file.
XOR_KEY = 1
IMAGE_FILE = 'FILENAME.jpg'
EXECUTABLE_FILE = 'FILENAME.exe'

image = open(IMAGE_FILE, 'rb').read()

fh = open(EXECUTABLE_FILE, 'rb')
exe_file_data = fh.read()
fh.close()

xor_data = ''
for val in exe_file_data:
	xor_data += chr(xor(ord(val), XOR_KEY))

fh = open('image_with_exe.jpg', 'wb')
new_image_data = image+xor_data
fh.write(new_image_data)
fh.close()
	
