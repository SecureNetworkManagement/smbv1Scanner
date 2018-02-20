#!/usr/bin/python
#
#Shad Malloy 
#shad.malloy@securenetworkmanagement.com
#
#
# 2/20/2018
#
# v .1
# Original
#
# v .2 
# Added Progress Bar
# Reduced SMB connection Timeout to improve performance
#
# Multithreaded scanner to verify SMBv1.
# Requires netaddr, pycrypto and impacket
# pip install pycrypto
# pip install impacket
# pip install netaddr
# pip install progress

# Imports
import argparse
import signal
import sys
import random
import time
import impacket
import os
from impacket.smbconnection import SMBConnection, smb, SMB_DIALECT
from netaddr import *
from threading import Thread
from progress.bar import ShadyBar

# Globals
threadCounter = 0
outputList = []

# Parse Commands
def commandLineParser():
	main_parser = argparse.ArgumentParser(
		prog='smbv1 scanner', 
        	description='******* * * * * * * * Check SMB for Version 1 Support * * * * * * * *******',
        	epilog='******* * * * * * * * * * * * * * * * * * * * * * * * * *******')

    	input_options_group = main_parser.add_mutually_exclusive_group()
    	input_options_group.add_argument('-i', '--input', nargs='+', help="IP Address in CIDR Notation")
    	input_options_group.add_argument('-f', '--file', nargs=1, help="file containing list of IPs to check")

   	main_parser.add_argument('-t', '--threads', default='8', help="Number of Threads")
    	main_parser.add_argument('-o', '--output', nargs=1, default='output.txt', help="Output File Name")
    	main_parser.add_argument('-v', '--version', action='version', version='%(prog)s 0.2')

	return main_parser

# Main
def main(argv):
	
	ipList = []
	parser = commandLineParser()
	if len(sys.argv)==1:
		parser.print_help()
		sys.exit(1)
	args = parser.parse_args()

        # Set Threads and Bar
	threadMax = 0
	barMax = 0

	if args.threads:
                threadMax = int(args.threads)
	else:
                threadMax = 256

        
	# Assign Options
	if args.input:
		ipList.append([args.input])
	elif args.file:
                # Check if file exists
                path = str(args.file).strip('[]\'')
                if os.path.exists(path):
                        ipFile = open(path, 'r')
                        for line in ipFile:
                                ipList.append([line])
                else:
                        print('. o O Input File Path Not Found ... EXITING O o .')
                        sys.exit(1)
	else:
		print ('No input file or CIDR range give, performing test on 127.0.0.1')
		ipList.append('127.0.0.1/32')

	
	# Create the randomized scan list
	ipListWorking = []
	for line in ipList:
                line = str(line).strip('[]\'\\n')
                if len(line) != 0:
                        for ip in IPNetwork(line).iter_hosts():
                                ipListWorking.append(ip)
        
	print('Number of addresses: ' + str(len(ipListWorking)))
	# Randomize list
	random.shuffle(ipListWorking)
	# Set barMax equal to number of hosts
	barMax = len(ipListWorking)

	# Thread Count Sanity Check
	if len(ipListWorking) < threadMax:
                threadMax = len(ipListWorking)
                print('Setting threads equal to number of hosts: ' + str(threadMax))

	# Progress Bar
	bar = ShadyBar('Scan Progress', max=barMax, suffix='%(index)d/%(max)d - %(percent).1f%% - %(eta)ds')

        # Actually do stuff
	for ip in ipListWorking:

		# update thread counter
		global threadCounter
		threadCounter += 1

		# wait if thread count is greater than maximum thread count
		while int(threadCounter) >= int(threadMax):
			time.sleep(.25)

		# scan worker thread
		else:
                        #print(str(ip) + ' thread ' + str(threadCounter))
			worker = Thread(target=doCheck, args=[ip])
			worker.setDaemon(True)
			worker.start()
			# Block until thread completes
			#worker.join()

		# Update Progress Bar
		bar.next()

	# Finish Bar
	bar.finish()	
	
	# Do reporting
    	print ('\n . x X Scan Completed X x .')
	global outputList
	
	sortResultsList =[]

	# Sort the list 
	sortResultsList = sorted(list(outputList))
	
        # Check if output file exists
	if args.output:        
		if os.path.exists(str(args.output).strip('[]\'')):
                        print('. x X File output.txt Exists ... Opening for Append X x .')
                        outputFile = open(str(args.output).strip('[]\''), 'a')
        	else:
                	outputFile = open(str(args.output).strip('[]\''), 'w')	
	
	if len(sortResultsList) == 0:
		print('No hosts found')
	else:
		print('Hosts report')
		for line in sortResultsList[:]:
                        print(line)
			outputFile.write(line + '\n')
	
	
	if args.output:	
		# Pause to allow file write
		time.sleep(1)	
		print('Results written to : ' + str(args.output).strip('[]\''))	
		outputFile.close()

# Perform Scan on IP(s)
def doCheck(ip):
	global outputList
	# Convert IP to iterable
	host = str(ip)
	# Set timeout to 2 seconds to improve performance
	timeoutSMB = 2
	try: 
		#Create connection strings for port 139 and 445        	
		s445 = SMBConnection('*SMBSERVER', remoteHost=host, sess_port=445, preferredDialect=smb.SMB_DIALECT, timeout=timeoutSMB)
		s139 = SMBConnection('*SMBSERVER', remoteHost=host, sess_port=139, preferredDialect=smb.SMB_DIALECT, timeout=timeoutSMB)
        	if isinstance(s445, SMBConnection):
                        print('SMBv1 Enabled (port 445): ' + host)
			outputList.append('SMBv1 Enabled (port 445): ' + str(host))
		elif isinstance(s139, SMBConnection):
                        print('SMBv1 Enabled (port 139): ' + host)
			outputList.append('SMBv1 Enabled (port 139): ' + str(host))
 
    	except Exception as e:
                #print('SMBv1 Not Detected: ' + host)
		outputList.append('SMBv1 Not Detected: ' + str(host))
	
	global threadCounter
	threadCounter -= 1	

# CTRL+C Handler
def customExit(signum, frame):
	#restore the original to prevent problems
    	signal.signal(signal.SIGINT, originalSigint)
    
    	#End message
    	print ('\n . x X Scan Cancelled By User X x .')
	global outputList
	sortResultsList =[]
	sortResultsList = outputList.sort()
	if len(sortResultsList) == 0:
		print('No hosts found before scan cancelled')
	else:
		print('Hosts found before scan cancelled')		
		for line in sortResultsList:
			print(line)
	
	print ('\n . x X Scan Cancelled X x .')

    	#exit
	sys.exit(1)	
	
# Custom Handler and Main
if __name__ == "__main__":
	#store original SIGINT handler
	originalSigint = signal.getsignal(signal.SIGINT)
	#use custom CTRL+C handler
    	signal.signal(signal.SIGINT, customExit)
    	#call main
	main(sys.argv[1:])

