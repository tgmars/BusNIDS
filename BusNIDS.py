#!/usr/bin/env python

# TODO: Update version number before push
# v0.0.41

from scapy.all import *

# Load the modbus extension module for Scapy as per the link at:
# https://lost-and-found-narihiro.blogspot.com.au/2012/11/python-scapy-how-to-load-extension.html

load_contrib('modbus')

# TODO: Move configuration variables to a configuration file
PORT = '502'
INTERFACE = "wlan0"
MASTER_IP="192.168.2.2"
CACHE_MAX_SIZE = 6
LOW_RISK=0.1
MED_RISK=0.5
HIGH_RISK=0.9
ERROR_RISK=2

packet_count = 0
cache_packet_count = packet_count % CACHE_MAX_SIZE
packet_risk = [] #List to contain risk of each individual packet
cache = [] #To be utilised
num_of_caches = 0 #Maintains a count of the number of caches that have been written to
cache_risk = [] #List to contain risk of each cached sequence of packets
ma_risk = 0.1
sigma = 0.341
num_detections=0

#Write to PCAP using wrpcap("filename.pcap",var_to_write)

tcp_communication = False

f = open('errorpackets.txt', 'a+')

def custom_display(packet):
    # TODO: Add statistics for each valid type of packet

    global packet_count
    global tcp_communication
    global num_of_caches
    global ma_risk
    global num_detections

    # Checks if there are Modbus ADUs (application data unit) in the packets, they contain the MBAP header, Function Code and Function Data.
    if packet.haslayer(ModbusADURequest) or packet.haslayer(ModbusADUResponse):
        # Used to generate a visualisation of the sniffed packet as a .pdf
        # packet[packetCount].pdfdump('packet.pdf')

        # Uncomment to present more details of the sniffed packet to the console.
        # return packet[packetCount].show()

        tcp_communication = False
        pr_local=determine_packet_risk(packet) # Assigns a risk value to the packet currently being processed in the corresponding packet_risk list.

        if 'Error' in last_layer_string(packet):
            f.write("\nBad Modbus packet : "+str(packet_count)+" Risk Level: "+str(pr_local)+"\n"+packet.show2(dump=True))
            print 'Error Packet reported src {} -> dst {} via PDU {}'.format(packet[IP].src, packet[IP].dst,last_layer_string(packet))
            packet_count += 1

        else:
            # Return that there is a valid modbus message request and the details of the function code.
            print "Valid ModbusADU packet. " + str(packet_count) + " Risk Level: " + str(pr_local) + " Type: " + last_layer_string(packet)
            packet_count += 1

        if len(cache) < CACHE_MAX_SIZE:
            cache.append(packet)
            packet_risk.append(pr_local)
            print "cache length: "+str(len(cache))
            print "risk length: "+str(len(packet_risk))
        else:
            cache_risk.append(get_cache_risk(packet_risk))

            print len(cache)
            curr_cache_risk=cache_risk[num_of_caches]
            print "curr_cache_risk: "+str(curr_cache_risk)
            print "ma risk stddev over: "+str(ma_risk+(ma_risk*sigma))
            if curr_cache_risk>(ma_risk+(ma_risk*sigma)):
                num_detections += 1
                print "Suspected Attack"
            print "Number of detections: "+str(num_detections)
            ma_risk=sum(cache_risk)/len(cache_risk)
            del cache[:]
            del packet_risk[:]
            num_of_caches += 1
            cache.append(packet)
            packet_risk.append(pr_local)

    # noinspection PyUnreachableCode
    if tcp_communication:
        return

    else:
        tcp_communication = True
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
    I apologise to anyone that reads this code.

    Returns:
        Null
    """
    # TODO: Add modifier to pr_local if IP source on incoming or IP dst on outgoing is different to MASTER_IP

    pr_local=0

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
        pr_local+=LOW_RISK
        print "Low PR"
        return pr_local


    elif (packet.haslayer(ModbusPDU15WriteFileRecordRequest) or packet.haslayer(ModbusPDU15WriteFileRecordResponse)
        or packet.haslayer(ModbusPDU16MaskWriteRegisterRequest) or packet.haslayer(ModbusPDU16MaskWriteRegisterResponse)
        or packet.haslayer(ModbusReadFileSubRequest) or packet.haslayer(ModbusReadFileSubResponse)
        or packet.haslayer(ModbusWriteFileSubRequest) or packet.haslayer(ModbusWriteFileSubResponse)):
        pr_local += MED_RISK
        print "Med PR"
        return pr_local

    elif (packet.haslayer(ModbusPDU05WriteSingleCoilRequest) or packet.haslayer(ModbusPDU05WriteSingleCoilResponse)
        or packet.haslayer(ModbusPDU06WriteSingleRegisterRequest) or packet.haslayer(ModbusPDU06WriteSingleRegisterResponse)
        or packet.haslayer(ModbusPDU0FWriteMultipleCoilsRequest) or packet.haslayer(ModbusPDU0FWriteMultipleCoilsResponse)
        or packet.haslayer(ModbusPDU10WriteMultipleRegistersRequest) or packet.haslayer(ModbusPDU10WriteMultipleRegistersResponse)
        or packet.haslayer(ModbusPDU17ReadWriteMultipleRegistersRequest) or packet.haslayer(ModbusPDU17ReadWriteMultipleRegistersResponse)):
        pr_local += HIGH_RISK
        print "High PR ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
        return pr_local

    elif (packet.haslayer(ModbusPDU01ReadCoilsError) or packet.haslayer(ModbusPDU02ReadDiscreteInputsError)
        or packet.haslayer(ModbusPDU03ReadHoldingRegistersError) or packet.haslayer(ModbusPDU04ReadInputRegistersError)
        or packet.haslayer(ModbusPDU05WriteSingleCoilError) or packet.haslayer(ModbusPDU06WriteSingleRegisterError)
        or packet.haslayer(ModbusPDU07ReadExceptionStatusError) or packet.haslayer(ModbusPDU0FWriteMultipleCoilsError)
        or packet.haslayer(ModbusPDU10WriteMultipleRegistersError) or packet.haslayer(ModbusPDU11ReportSlaveIdError)
        or packet.haslayer(ModbusPDU14ReadFileRecordError) or packet.haslayer(ModbusPDU15WriteFileRecordError)
        or packet.haslayer(ModbusPDU16MaskWriteRegisterError) or packet.haslayer(ModbusPDU17ReadWriteMultipleRegistersError)
        or packet.haslayer(ModbusPDU18ReadFIFOQueueError) or packet.haslayer(ModbusPDU2B0EReadDeviceIdentificationError)):
        pr_local += ERROR_RISK
        print "Error PR ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
        return pr_local

def get_cache_risk(cache_of_packet_risks):
    """Assigns a risk level to a cache of CACHE_MAX_SIZE packets
        based on the average risk level in the cache.
        Returns:
        Average value of a number CACHE_MAX_SIZR packet risk
    """
    return sum(cache_of_packet_risks)/len(cache_of_packet_risks)

## Configure the sniff scapy argument for port 502 on the Rpi wireless interface and only sniff MAX_PACKETS  packets.
pkt = sniff(filter="port " + PORT, iface=INTERFACE, prn=custom_display)
#Do a 100 packet sniff, analyse and report, rinse and repeat
f.close()