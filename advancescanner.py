#!/usr/bin/python

import optparse
from socket import *
from threading import *

def connScan(tgtHost, tgtPort):
	try:
		sock = socket(AF_INET,SOCK_STREAM)
		sock.connect(tgtHost, tgtPort)
		print ('[+] %d/tcp Open' %tgtPort)
	except:
		print ('[-] %d/tcp Closed' %tgtPort)
	finally:
		sock.close()
def portScan(tgtHost, tgtPorts):
	try:
		tgtIp = gethostbyname(tgtHost)
	except:
		print ("Unknown Host %S" %tgtHost)
	try:
		tgtName = gethostbyaddr(tgtIp)
		print ('[+] Scan Result for :' %tgtName[0])
	except:
		print ('[+] Scan Result for :' + tgtIp)
	setdefaulttimeout(2)
	for tgtPort in tgtPorts:
		t = Thread(target=connScan, args=(tgtHost,int(tgtPort)))
		t.start()
def lululu():
	parser = optparse.OptionParser('Usage of the program: ' + '-H <Target Host> -p <Target Port>')
	parser.add_option('-H', dest='tgtHost', type='string', help='Specify target host')
	parser.add_option('-p', dest='tgtPort', type='string', help='specify target ports seprated using comma')
	(options, args) = parser.parse_args()
	tgtHost = options.tgtHost
	tgtPorts = str(options.tgtPort).split(',')
	if (tgtHost == None) | (tgtPorts[0] == None):
		print parser.usage
		exit(0)
	portScan(tgtHost, tgtPorts)

lululu()
