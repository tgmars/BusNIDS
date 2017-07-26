#!/usr/bin/env python

#  v0.0.1

from scapy.all import *
import argparse

load_contrib('modbus')

#Parse arguments from command line at runtime
parser = argparse.ArgumentParser(description="Sends a variety of valid and invalid Modbus TCP packets to a user-defined IP address to test robustness of a PLC or IDS.")
parser.add_argument("dst_ip", help="IP address of Modbus PLC or IDS to test.")
parser.add_argument("dst_port", type=int, help="Port that the Modbus TCP service is running on the destination machine.")
args=parser.parse_args()

#Create a TCP connection to the specified address
testSock = socket.socket()
testSock.connect((args.dst_ip,502))
testStream = StreamSocket(testSock)

#Create various packets to send to the destination
