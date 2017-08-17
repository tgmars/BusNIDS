#!/usr/bin/env python

# TODO: Update version number before push
# v0.0.31

from scapy.all import *

# Load the modbus extension module for Scapy as per the link at:
# https://lost-and-found-narihiro.blogspot.com.au/2012/11/python-scapy-how-to-load-extension.html

load_contrib('modbus')

MAX_PACKETS = 400
PORT = '502'
INTERFACE = "wlan0"

packet_count = 0
packet_risk = [] #Empty list which will contain risk level of each packet.
cache=[] #To be utilised
#To write to PCAP file, use wrpcap("filename.pcap",var_to_write)

low_risk=frozenset(ModbusPDU01ReadCoilsRequest,ModbusPDU01ReadCoilsResponse,ModbusPDU02ReadDiscreteInputsRequest,ModbusPDU02ReadDiscreteInputsResponse,
             ModbusPDU03ReadHoldingRegistersRequest,ModbusPDU03ReadHoldingRegistersResponse,ModbusPDU04ReadInputRegistersRequest,ModbusPDU04ReadInputRegistersResponse,
             ModbusPDU07ReadExceptionStatusRequest,ModbusPDU07ReadExceptionStatusResponse,ModbusPDU11ReportSlaveIdRequest,ModbusPDU11ReportSlaveIdResponse,
             ModbusPDU14ReadFileRecordRequest,ModbusPDU14ReadFileRecordResponse,ModbusPDU18ReadFIFOQueueRequest,ModbusPDU18ReadFIFOQueueResponse,
             ModbusPDU2B0EReadDeviceIdentificationRequest,ModbusPDU2B0EReadDeviceIdentificationResponse)

med_risk=frozenset(ModbusPDU15WriteFileRecordRequest,ModbusPDU15WriteFileRecordResponse,ModbusPDU16MaskWriteRegisterRequest,ModbusPDU16MaskWriteRegisterResponse,
             ModbusReadFileSubRequest,ModbusReadFileSubResponse,ModbusWriteFileSubRequest,ModbusWriteFileSubResponse)

high_risk=frozenset(ModbusPDU05WriteSingleCoilRequest,ModbusPDU05WriteSingleCoilResponse,ModbusPDU06WriteSingleRegisterRequest,ModbusPDU06WriteSingleRegisterResponse,
              ModbusPDU0FWriteMultipleCoilsRequest,ModbusPDU0FWriteMultipleCoilsResponse,ModbusPDU10WriteMultipleRegistersRequest,ModbusPDU10WriteMultipleRegistersResponse,
              ModbusPDU17ReadWriteMultipleRegistersRequest,ModbusPDU17ReadWriteMultipleRegistersResponse)

error_risk=frozenset(ModbusPDU01ReadCoilsError,ModbusPDU02ReadDiscreteInputsError,ModbusPDU03ReadHoldingRegistersError,ModbusPDU04ReadInputRegistersError,ModbusPDU05WriteSingleCoilError,
               ModbusPDU06WriteSingleRegisterError,ModbusPDU07ReadExceptionStatusError,ModbusPDU0FWriteMultipleCoilsError,ModbusPDU10WriteMultipleRegistersError,
               ModbusPDU11ReportSlaveIdError,ModbusPDU14ReadFileRecordError,ModbusPDU15WriteFileRecordError,ModbusPDU16MaskWriteRegisterError,
               ModbusPDU17ReadWriteMultipleRegistersError,ModbusPDU18ReadFIFOQueueError,ModbusPDU2B0EReadDeviceIdentificationError)

tcpcommunication = False

f = open('errorpackets.txt', 'a+')


def custom_display(packet):
    # TODO: Add statistics for each valid type of packet

    global packet_count
    global tcpcommunication

    # Checks if there are Modbus ADUs (application data unit) in the packets, they contain the MBAP header, Function Code and Function Data.
    if packet.haslayer(ModbusADURequest) or packet.haslayer(ModbusADUResponse):
        # Used to generate a visualisation of the sniffed packet as a .pdf
        # packet[packetCount].pdfdump('packet.pdf')

        # Uncomment to present more details of the sniffed packet to the console.
        # return packet[packetCount].show()

        tcpcommunication = False

        determine_packet_risk(packet) # Assigns a risk value to the packet currently being processed in the corresponding packet_risk list.

        if 'Error' in last_layer_string(packet):
            f.write("\nBad Modbus packet : "+str(packet_count)+" Risk Level: "+str(packet_risk[packet_count])+"\n"+packet.show2(dump=True))
            return 'Error Packet reported src {} -> dst {} via PDU {}'.format(packet[IP].src, packet[IP].dst,last_layer_string(packet))
        else:
            # Return that there is a valid modbus message request and the details of the function code.
            return "Valid ModbusADU packet. Risk Level: "+str(packet_risk[packet_count])+" Type: " + last_layer_string(packet)

        packet_count += 1
    # noinspection PyUnreachableCode
    if tcpcommunication:
        return ''

    else:
        tcpcommunication = True
        return "TCP Handshaking..."


def last_layer_string(packet):
    """Function to return the top layer of a packet as a string.

	Returns:
	    The top layer of a scapy packet as a string.
	"""
    return packet.summary().split("/")[-1].strip('\'')

def determine_packet_risk(packet):
    if low_risk in packet:
        packet_risk[packet_count]=0.25

    if med_risk in packet:
        packet_risk[packet_count]=0.5

    if high_risk in packet:
        packet_risk[packet_count]=0.75

    if error_risk in packet:
        packet_risk[packet_count]=0.95


## Configure the sniff scapy argument for port 502 on the Rpi wireless interface and only sniff MAX_PACKETS  packets.
pkt = sniff(filter="port " + PORT, iface=INTERFACE, prn=custom_display)
#Do a 100 packet sniff, analyse and report, rinse and repeat
f.close()