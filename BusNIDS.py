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

med_risk={ModbusPDU15WriteFileRecordRequest,ModbusPDU15WriteFileRecordResponse,ModbusPDU16MaskWriteRegisterRequest,ModbusPDU16MaskWriteRegisterResponse,
             ModbusReadFileSubRequest,ModbusReadFileSubResponse,ModbusWriteFileSubRequest,ModbusWriteFileSubResponse}

high_risk={ModbusPDU05WriteSingleCoilRequest,ModbusPDU05WriteSingleCoilResponse,ModbusPDU06WriteSingleRegisterRequest,ModbusPDU06WriteSingleRegisterResponse,
              ModbusPDU0FWriteMultipleCoilsRequest,ModbusPDU0FWriteMultipleCoilsResponse,ModbusPDU10WriteMultipleRegistersRequest,ModbusPDU10WriteMultipleRegistersResponse,
              ModbusPDU17ReadWriteMultipleRegistersRequest,ModbusPDU17ReadWriteMultipleRegistersResponse}

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
    """Assigns a risk level to a packet depending on the type of ModbusPDU packet
    The risk level is assigned in the packet_risk list index corresponding to the
    packets location in the packet pkt array.

    Returns:
        Null
    """
    print "Determining packet risk..."
    if (packet.haslayer(ModbusPDU01ReadCoilsRequest) or packet.haslayer(ModbusPDU01ReadCoilsResponse)
        or packet.haslayer(ModbusPDU02ReadDiscreteInputsRequest) or packet.haslayer(ModbusPDU02ReadDiscreteInputsResponse)
        or packet.haslayer(ModbusPDU03ReadHoldingRegistersRequest) or packet.haslayer(ModbusPDU03ReadHoldingRegistersResponse)
        or packet.haslayer(ModbusPDU04ReadInputRegistersRequest) or packet.haslayer(ModbusPDU04ReadInputRegistersResponse)
        or packet.haslayer(ModbusPDU07ReadExceptionStatusRequest) or packet.haslayer(ModbusPDU07ReadExceptionStatusResponse)
        or packet.haslayer(ModbusPDU11ReportSlaveIdRequest) or packet.haslayer(ModbusPDU11ReportSlaveIdResponse)
        or packet.haslayer(ModbusPDU14ReadFileRecordRequest) or packet.haslayer(ModbusPDU14ReadFileRecordResponse)
        or packet.haslayer(ModbusPDU18ReadFIFOQueueRequest) or packet.haslayer(ModbusPDU18ReadFIFOQueueResponse)
        or packet.haslayer(ModbusPDU2B0EReadDeviceIdentificationRequest) or packet.haslayer(ModbusPDU2B0EReadDeviceIdentificationResponse)):
        packet_risk.append(0.25)
        print "Low PR"

    if med_risk in packet:
        packet_risk.append(0.5)
        print "Med PR"

    if high_risk in packet:
        packet_risk.append(0.75)
        print "High PR"

    if (packet.haslayer(ModbusPDU01ReadCoilsError) or packet.haslayer(ModbusPDU02ReadDiscreteInputsError)
        or packet.haslayer(ModbusPDU03ReadHoldingRegistersError) or packet.haslayer(ModbusPDU04ReadInputRegistersError)
        or packet.haslayer(ModbusPDU05WriteSingleCoilError) or packet.haslayer(ModbusPDU06WriteSingleRegisterError)
        or packet.haslayer(ModbusPDU07ReadExceptionStatusError) or packet.haslayer(ModbusPDU0FWriteMultipleCoilsError)
        or packet.haslayer(ModbusPDU10WriteMultipleRegistersError) or packet.haslayer(ModbusPDU11ReportSlaveIdError)
        or packet.haslayer(ModbusPDU14ReadFileRecordError) or packet.haslayer(ModbusPDU15WriteFileRecordError)
        or packet.haslayer(ModbusPDU16MaskWriteRegisterError) or packet.haslayer(ModbusPDU17ReadWriteMultipleRegistersError)
        or packet.haslayer(ModbusPDU18ReadFIFOQueueError) or packet.haslayer(ModbusPDU2B0EReadDeviceIdentificationError)):
        packet_risk.append(0.95)
        print "Error PR"


## Configure the sniff scapy argument for port 502 on the Rpi wireless interface and only sniff MAX_PACKETS  packets.
pkt = sniff(filter="port " + PORT, iface=INTERFACE, prn=custom_display)
#Do a 100 packet sniff, analyse and report, rinse and repeat
f.close()