#!/usr/bin/env python

#TODO: Update version number before push
# v0.0.8

from scapy.all import *

#Load the modbus extension module for Scapy as per the link at:
#https://lost-and-found-narihiro.blogspot.com.au/2012/11/python-scapy-how-to-load-extension.html

load_contrib('modbus')

MAX_PACKETS = 25
PORT = '502'
INTERFACE = "wlan0"



packetCount = 0

def customDisplay(packet):

	#TODO: Add statistics for each valid type of packet

	global packetCount


    #Checks if there are Modbus ADUs (application data unit) in the packets, they contain the MBAP header, Function Code and Function Data.
	if packet.haslayer(ModbusADURequest): #Change this so that there is a list of 'layers' and if incldued then execute.

		packetCount += 1
		print packetCount
		#Used to generate a visualisation of the sniffed packet as a .pdf
		#packet[packetCount].pdfdump('packet.pdf')

		#Uncomment to present more details of the sniffed packet to the console.
		#return packet[packetCount].show()
		if "error" in packet:
			return 'src {} -> dst {} {} -> Likely malformed packet'.format(packet[packetCount][2].src, packet[packetCount][2].dst, packet.lastlayer())
		else:
            #Return that there is a valid modbus message request and the details of the function code.
			return "Valid ModbusADURequest. Type: "+str(packet.lastlayer())

	if packet.haslayer(ModbusADUResponse): #Change this so that there is a list of 'layers' and if incldued then execute.
		packetCount += 1
		print packetCount
		#Used to generate a visualisation of the sniffed packet as a .pdf
		#packet[packetCount].pdfdump('packet.pdf')

		#Uncomment to present more details of the sniffed packet to the console.
		#return packet[packetCount].show()
		if "error" in packet:
			return 'src {} -> dst {} {} -> Likely malformed packet'.format(packet[packetCount][2].src, packet[packetCount][2].dst, packet.lastlayer())
		else:
            # Return that there is a valid modbus response request and the details of the function code.
			return "Valid ModbusADUResponse. Type: "+str(packet.lastlayer())

	else: 
		return "Not Modbus Protocol - likely TCP handshaking"

## Configure the sniff scapy argument for port 502 on the Rpi wireless interface and only sniff MAX_PACKETS  packets.

pkt=sniff(filter="port "+PORT, iface=INTERFACE, count = MAX_PACKETS,  prn=customDisplay)


