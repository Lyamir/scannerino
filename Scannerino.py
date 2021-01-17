# Scannerino version 2.4
#
# Before running the script, the following dependencies need to be installed:
#   - python3-nmap  v1.4.9
#   - tabulate      v0.8.7

import os
import sys
import subprocess
import time
import ipaddress
import nmap3
import json
import signal
from datetime import datetime
from tabulate import tabulate

nmap = nmap3.Nmap()                             # Accessing list of basic Nmap functions
nmap_scan = nmap3.NmapScanTechniques()          # Accessing list of Nmap scan technique functions
nmap_host = nmap3.NmapHostDiscovery()           # Accessing list of Nmap host discovery functions

#Declaring Global Variables
port = 443                                      # Default port if no port is specified
startRange = None                               # Default start range
endRange = None                                 # Default end range
runtime = False                                 # Default show runtime
startTime = time.time()                         # Starting time in which the command was run
hostList = []                                   # List of host/s to be scanned

def portScan(port):

    for host in hostList:

        #CONNECT Scan
        con_res=nmap_scan.nmap_tcp_scan(host["address"], args="-Pn -p" + str(port))
        if host["address"] in con_res:
            portList = con_res[host["address"]]["ports"]
            
            host.update({"con_res": "Not Responding"})
            for portHolder in portList:
                if portHolder["portid"] == str(port):
                    host.update({"con_res": portHolder["state"]})
        else:
            host.update({"con_res": "Not Responding"})
            
        #SYN Scan
        syn_res=nmap_scan.nmap_syn_scan(host["address"], args="-Pn -p" + str(port))
        if host["address"] in syn_res:
            portList = syn_res[host["address"]]["ports"]
            host.update({"syn_res": "Not Responding"})
            for portHolder in portList:
                if portHolder["portid"] == str(port):
                    host.update({"syn_res": portHolder["state"]})
        else:
            host.update({"syn_res": "Not Responding"})
        
        #XMAS Scan
        xmas_res= nmap_host.nmap_portscan_only(host["address"], args="-Pn -sX -p" + str(port))
        if host["address"] in xmas_res:
            portList = xmas_res[host["address"]]["ports"]
            
            host.update({"xmas_res": "Not Responding"})
            for portHolder in portList:
                if portHolder["portid"] == str(port):
                    host.update({"xmas_res": portHolder["state"]})
        else:
            host.update({"xmas_res": "Not Responding"})
        
        #FIN Scan
        fin_res=nmap_scan.nmap_fin_scan(host["address"], args="-Pn -p" + str(port))
        if host["address"] in fin_res:
            portList = fin_res[host["address"]]["ports"]
            
            host.update({"fin_res":"Not Responding"})
            for portHolder in portList:
                if portHolder ["portid"] == str(port):
                    host.update({"fin_res": portHolder["state"]})
        else:
            host.update({"fin_res": "Not Responding"})

        #NULL Scan
        null_res= nmap_host.nmap_portscan_only(host["address"], args="-Pn -sN -p" + str(port))
        if host["address"] in null_res:
            portList = null_res[host["address"]]["ports"]
            
            host.update({"null_res": "Not Responding"})
            for portHolder in portList:
                if portHolder["portid"] == str(port):
                    host.update({"null_res": portHolder["state"]})
        else:
            host.update({"null_res": "Not Responding"})
        
        #ACK Scan
        ack_res= nmap_host.nmap_portscan_only(host["address"], args="-Pn -sA -p" + str(port))
        if host["address"] in ack_res:
            portList = ack_res[host["address"]]["ports"]
            
            host.update({"ack_res": "Not Responding"})
            for portHolder in portList:
                if portHolder["portid"] == str(port):
                    host.update({"ack_res": portHolder["state"]})
        else:
            host.update({"ack_res": "Not Responding"})  
    formatResult()
    
#Called to format the Array of hostList into a fancy grid format to be properly shown
def formatResult():
    print('Showing formatted results')
    header = ('IP Address', 'ICMP','CONN','SYN','XMAS','FIN','NULL','ACK')
    scan_results = [x.values() for x in hostList]
    print(tabulate(scan_results,header,tablefmt="fancy_grid"))

#Validates IP address
def ipChecker(ipAdd):
    def validNums(s):
        try: return str(int(s)) == s and 0 <= int(s) <= 255
        except: return False
    if(ipAdd.count(".") == 3 and all(validNums(i) for i in ipAdd.split("."))):
        return True
    return False

#Pings specified individual host with designated port for ICMP
def pingIndiv(host,port):
    address = ipaddress.IPv4Address(host)
    print(f'Scanning {host} at port {port}')
    result = nmap_host.nmap_no_portscan(str(address), args ='-PE')
    
    if host in result:
        hostList.append({'address':host,'state': result[host]["state"]["state"]})
    else:
        hostList.append({'address':host,'state':'down'})
    portScan(port)
    
#Pings specified range of hosts with designated port for ICMP
def pingMany(startRange, endRange,port):
    print(f'Scanning hosts {startRange}-{endRange} at port {port}')
    hostRange = int(ipaddress.IPv4Address(endRange)) - int(ipaddress.IPv4Address(startRange))
    address = ipaddress.IPv4Address(startRange)
    for i in range(hostRange +1):
        result = nmap_host.nmap_no_portscan(str(address), args ='-PE')
        if str(address) in result:
            hostList.append({'address':str(address), 'state': result[str(address)]["state"]["state"]})
        else:
            hostList.append({'address':str(address), 'state': 'down'})  
        address +=1   
    portScan(port)
    
#
def exitProgram(signalnum,frame):
    print('Interrupting Script. Exiting Program')
    sys.exit(0)

signal.signal(signal.SIGINT, exitProgram)

# Script Arguments
if len(sys.argv) > 1:
    for arg in sys.argv:
        if(arg == '-v'):
            print('Scannerino v2.4')
            print('Created by Carlos Antonio Doble as a project for an Ethical Hacking class, and allows the scanning of hosts for ICMP and TCP scannings')
            print('NOTE: This is a LINUX based application. The script may or may not be compatible with other OS.')
            print('NOTE: To use the tool to its full potential Admin privileges or Root privileges need to be used when running the App')
            print('In order to use this script the following Python packages need to be installed:')
            print('         - python3-nmap  v1.4.9')
            print('         - tabulate      v0.8.7')
        elif(arg == '-h'):
            print('         -h: Help command')
            print('         sudo python3 Scannerino.py -h')
            print('         -v: Displays version number')
            print('         sudo python3 Scannerino.py -v')
            print('         -p: Specifies port number')
            print('         sudo python3 Scannerino.py host 10.10.0.11 -p 22')
            print('         host: Specify a <host> or range of hosts <starting range> <end range> to scan')
            print('         sudo python3 Scannerino.py host 10.10.0.11 -p 22')
            print('         sudo python3 Scannerino.py host 10.10.0.11 10.10.0.13 -p 22')
            print('         -t: Displays total time running the script')
            print('         sudo python3 Scannerino.py -t')
        elif(arg == '-t'):
            runtime = True
        elif(arg == '-p'):
            if(sys.argv[sys.argv.index(arg) +1].isnumeric()):
                if(int(sys.argv[sys.argv.index(arg) +1]) >=0 and int(sys.argv[sys.argv.index(arg) +1]) <=65535):
                    port = int(sys.argv[sys.argv.index(arg) +1])
                else:
                    print('Invalid port number')
            else:
                print('Invalid port number')
        if(arg == 'host'):
            if(ipChecker(sys.argv[sys.argv.index(arg)+1])):
                startRange = sys.argv[sys.argv.index(arg) +1]
                
                if(sys.argv.index(arg) + 2 <len(sys.argv)):
                    if(ipChecker(sys.argv[sys.argv.index(arg)+2])):
                        endRange = sys.argv[sys.argv.index(arg)+2]
            else:
                print('Invalid Starting IP Address Range')

if startRange is not None:
    if endRange is not None:
        pingMany(startRange,endRange,port)
    else:
        pingIndiv(startRange,port)
if runtime:
    print('Script runtime:', time.time() - startTime)