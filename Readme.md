smbv1Scanner.py

A multi-threaded python scanner that uses the impacket libraries to negotiate an SMBv1 connection. 

Requires netaddr, pycrypto and impacket
Install with:
	pip install pycrypto
	pip install impacket
	pip install netaddr
	
python smbv1Scanner.py [*options]
usage: smbv1 scanner [-h] [-i INPUT [INPUT ...] | -f FILE] [-t THREADS]
                     [-o OUTPUT] [-v]

******* * * * * * * * Check SMB for Version 1 Support * * * * * * * *******

optional arguments:
  -h, --help            show this help message and exit
  -i INPUT [INPUT ...], --input INPUT [INPUT ...]
                        IP Address in CIDR Notation
  -f FILE, --file FILE  file containing list of IPs to check
  -t THREADS, --threads THREADS
                        Number of Threads
  -o OUTPUT, --output OUTPUT
                        Output File Name
  -v, --version         show program's version number and exit

******* * * * * * * * * * * * * * * * * * * * * * * * * *******


