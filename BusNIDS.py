#!/usr/bin/env python

# TODO: Update version number before push
# v0.0.21

from scapy.all import *

# Load the modbus extension module for Scapy as per the link at:
# https://lost-and-found-narihiro.blogspot.com.au/2012/11/python-scapy-how-to-load-extension.html

load_contrib('modbus')

MAX_PACKETS = 400
PORT = '502'
INTERFACE = "wlan0"

packetCount = 0
tcpcommunication = False

f = open('errorpackets.txt', 'a+')


def customDisplay(packet):
    # TODO: Add statistics for each valid type of packet

    global packetCount
    global tcpcommunication

    # Checks if there are Modbus ADUs (application data unit) in the packets, they contain the MBAP header, Function Code and Function Data.
    if packet.haslayer(ModbusADURequest) or packet.haslayer(ModbusADUResponse):

        packetCount += 1
        # print packetCount
        # Used to generate a visualisation of the sniffed packet as a .pdf
        # packet[packetCount].pdfdump('packet.pdf')

        # Uncomment to present more details of the sniffed packet to the console.
        # return packet[packetCount].show()
        print str('Error' in lastlayerString(packet))
        tcpcommunication = False
        if 'Error' in lastlayerString(packet):
            f.write("\nModbus packet: "+str(packetCount)+"\n"+packet.show2(dump=True))
            return 'Malformed Packet: src {} -> dst {} via protocol {}'.format(packet[IP].src, packet[IP].dst,lastlayerString(packet))
        else:
            # Return that there is a valid modbus message request and the details of the function code.
            return "Valid ModbusADU packet. Type: " + lastlayerString(packet)

    # noinspection PyUnreachableCode
    if tcpcommunication:
        return ''

    else:
        tcpcommunication = True
        return "TCP Handshaking..."


def lastlayerString(packet):
    """Function to return the top layer of a packet as a string.

	Returns:
	    The top layer of a scapy packet as a string.
	"""
    return packet.summary().split("/")[-1].strip('\'')


## Configure the sniff scapy argument for port 502 on the Rpi wireless interface and only sniff MAX_PACKETS  packets.
pkt = sniff(filter="port " + PORT, iface=INTERFACE, prn=customDisplay)
f.close()