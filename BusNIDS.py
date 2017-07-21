#!/usr/bin/env python


from scapy.all import *

#Load the modbus extension module for Scapy as per the link at:
#https://lost-and-found-narihiro.blogspot.com.au/2012/11/python-scapy-how-to-load-extension.html

load_contrib('modbus')

MAX_PACKETS = 25
PORT = '502'
INTERFACE = "wlan0"

packetCount = -1

def customDisplay(packet):
	if packet.haslayer(ModbusADURequest):
		global packetCount
		packetCount += 1
		print packetCount
		#Used to generate a visualisation of the sniffed packet as a .pdf
		#packet[packetCount].pdfdump('packet.pdf')

		#Uncomment to present more details of the sniffed packet to the console.
		#return packet[packetCount].show()
		if "error" in packet:
			return 'src {} -> dst {} {} -> Likely malformed packet'.format(packet[packetCount][2].src, packet[packetCount][2].dst, packet.getlayer())
		else:
			return "Valid ModbusADURequest"
	else: 
		return "not modbus traffic" 

## Configure the sniff scapy argument for port 502 on the Rpi wireless interface and only sniff MAX_PACKETS  packets.

pkt=sniff(filter="port "+PORT, iface="wlan0", count = MAX_PACKETS,  prn=customDisplay)


