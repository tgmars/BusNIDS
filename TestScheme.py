#!/usr/bin/env python

#  v0.0.3

from scapy.all import *
import argparse
import time

load_contrib('modbus')

NUM_PACKETS_TO_SNIFF=100

#Parse arguments from command line at runtime
parser = argparse.ArgumentParser(description="Sends a variety of valid and invalid Modbus TCP packets from an 'attacker' to a user-defined IP address to test robustness of a PLC or IDS.")
parser.add_argument("dst_ip", help="IP address of Modbus PLC or IDS to test.")
parser.add_argument("dst_port", type=int, help="Port that the Modbus TCP service is running on the destination machine. If unsure, use port 502.")
args=parser.parse_args()

#Create a TCP connection to the specified address
sock = socket.socket()
sock.connect((args.dst_ip,502))
stream = StreamSocket(sock)

#Create various attack packets to send to the destination

read_coils=ModbusADURequest()/ModbusPDU01ReadCoilsRequest(startAddr=0,quantity=3)
read_discrete_inputs=ModbusADURequest()/ModbusPDU02ReadDiscreteInputsRequest(startAddr=2,quantity=1)
errorpacket=ModbusADURequest()/ModbusPDU10WriteMultipleRegistersRequest(startingAddr=1,outputsValue=[13],quantityRegisters=5L)
for i in range(0,(NUM_PACKETS_TO_SNIFF/4)-1):
    stream.sr(read_coils)
    stream.sr(read_discrete_inputs)
    time.sleep(0.5)

#Send the desired packets
#response=stream.sr(errorpacket)
stream.sr(errorpacket)