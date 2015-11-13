import argparse
import os
import multiprocessing as mp
import Queue
from operator import xor
import time

#Version 1.0

#The script xor's each byte in a file with an xor key. 
#It then searches for executable files which have been embedded.
#The script currently runs through 256 xor keys.

def main():

	try:
		parser = argparse.ArgumentParser(description='Extract obfuscated executables from files')
		parser.add_argument('-f', type=str, dest="filename", help='Extract executables from file')
		parser.add_argument('-d', type=str, dest="directory", help='Extract executables from files in a directory')
		parser.add_argument('-o', type=str, dest="output_directory", help='Save extracted executables in the output directory')
		parser.add_argument('-s', type=int, dest="max_file_size", help='Maximum file size of a file in a directory')
		parser.add_argument('-v', dest='verbose', help='Verbose output', action='store_true')
		parser.set_defaults(verbose=False)

		args = parser.parse_args()

		if not args.filename or args.directory:
			print 'Need a filename or directory - Check usage: extractxor.py -h'
		elif args.filename:
			filename = args.filename
		elif args.directory:
			directory = args.directory
		else:
			print 'Need a filename or directory - Check usage: extractxor.py -h'

		xor_key_Queue, file_data_Queue = start_processes(args)	
	
		if filename:
			process_file(args, filename, xor_key_Queue, file_data_Queue)
		
		if args.directory:
			if not os.path.exists(directory):
				print 'The directory does not exist: ' + directory
			
		if args.directory:
			for root, directory, filenames in os.path.walk(directory):
				for filename in filenames:
					filepath = os.path.join(root, filename)
					process_file(args, filepath, xor_key_Queue, file_data_Queue)
	except Exception,e:
		print e
			
def start_processes(args):

	try:
	
		#Number of analyser processes
		NUMBER_OF_PROCESSES = 4
		process_handles = []

		#Start Queues 
		xor_key_Queue = mp.Queue()
		file_data_Queue = mp.Queue()
		
		#Start analyser processes
		for i in xrange(NUMBER_OF_PROCESSES):
			process_handle = mp.Process(target = process_controller, args = (args, xor_key_Queue, file_data_Queue))
			process_handles.append(process_handle)
			process_handle.start()
		
		#Return queues back to main method
		return xor_key_Queue, file_data_Queue
		
	except Exception,e:
		print e
	
def process_file(args, filepath, xor_key_Queue, file_data_Queue):

	try:
		if not os.path.exists(filepath):
			print 'The file does not exist: ' + filepath
			return
		
		fh = open(filepath, 'rb')
		file_data = fh.read()
		fh.close()
		
		if args.max_file_size and args.directory:
			#Ignore files over this size
			if len(file_data) > args.max_file_size:
				if args.verbose:
					print 'The file is over ' + str(args.max_file_size) + ' bytes'
				return
		
		#Convert integer value from binary value using ord
		#Do this now so the conversion isn't constantly repeated for each xor key.
		file_data = [ord(i) for i in file_data]
		
		#Distribute xor_keys between analyer processes.
		xor_keys = 256
		for i in xrange(xor_keys):
			xor_key_Queue.put(i)
			
		file_data_Queue.put(file_data)
		file_data_Queue.put(file_data)
		file_data_Queue.put(file_data)
		file_data_Queue.put(file_data)
		
	except Exception,e:
		print e
	
def process_controller(args, xor_key_Queue, file_data_Queue):
	
	try:
		#Each process requests a copy of the file data
		file_data = file_data_Queue.get()
		
		if args.verbose:
			start = time.time()	
		
		while True:
		
			#xor'd file data is stored in a list to improve speed
			xor_data = []

			#Process requests a key from the xor key queue
			try:
				xor_key = xor_key_Queue.get(block = False)
			except Exception,e:
				break

			#xor file data one byte at a time
			#xor integer with xor_key
			#Convert back to ASCII - chr
			#Hex - 16 * 16 = 256 = 256 keys
			#The file will still run, even if there are non-executable bytes appended.
			#The executable can be embedded anywhere in the file.
			for val in file_data:
				xor_data.append(chr(xor(val, xor_key)))

			#join the list - rebuilding the file
			xor_data = ''.join(xor_data)
			
			#Search for executables in the file data
			executable_file_search(args, xor_data)
		
		if args.verbose:
			done = time.time()
			elapsed = done - start
			print 'Process analysed data for ' + str(elapsed) + ' seconds'
			
	except Exception,e:
		print e
	
def executable_file_search(args, xor_data):

	try:
		# Check the file header is in the file before procceeding. 
		# Note, the file header can also be ZM.
		if not 'MZ' in xor_data:
			return
		
		MZ_count = 0
		executable_filecount = 1
		
		while True:
		
			#For the first interation, start searching for MZ from the start of the file.
			if MZ_count == 0:
				start_index = 0
			
			#Find the lowest location/index of MZ in the file data
			try:
				header_index = xor_data.index('MZ', start_index)
			except ValueError,e:
				#End of file, exit
				break
			
			#Increment MZ_count for every instance of MZ identified in the file data
			if header_index:
				MZ_count += 1
				
			#Find PE Header. At offset 60 (0x3C) from the beginning of the DOS header is a pointer to the Portable Executable (PE) File header.
			#Add the header_index to the PE header pointer points to it's position from the start of the file.
			pe_header_pointer = header_index + 60
			#Convert the PE header pointer value to an integer, and add the header_index.
			#The pe_header_position value now points to the position of the pe header from the start of the file data.
			pe_header_position = header_index + ord(xor_data[pe_header_pointer])

			#Extract bytes where an executable stores the value 'PE'
			PE_header_start_values = xor_data[pe_header_position: pe_header_position + 2]
			
			#The portable executable optional header is not optional, except of COFF object files.
			if PE_header_start_values == 'PE':
				#If the values match extract the file data.
				executable = xor_data[header_index:]
				
				#Write the data to a file. It doesn't matter if the executable file has random characters appended, as it will still execute.
				filename = 'executable_'+str(executable_filecount)+'.exe'
				if args.output_directory:
					#Write file to the output directory
					filepath = os.path.join(args.output_directory, filename)
				else:
					#Write file to the current directory
					filepath = filename
				
				if args.verbose:
					print 'Extracting executable file: ' + filename
				
				f = open(filepath, 'wb')
				f.write(executable)
				f.close()
				executable_filecount += 1
			
			#For the next loop interation, start searching the file data from the current position of MZ in the file.
			start_index = header_index + 1
			
	except Exception,e:
		print e
		
if __name__ == '__main__':
	mp.freeze_support()
	main()

