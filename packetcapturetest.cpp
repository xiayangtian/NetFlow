#include "IPv4Layer.h"
#include "Packet.h"
#include "PcapFileDevice.h"
#include "stdlib.h"
#include "PcapLiveDevice.h"
#include "PcapLiveDeviceList.h"
#include "PlatformSpecificUtils.h"
#include <iostream>
#include <stdio.h>
using namespace std;

//counting the packets
struct PacketStats
	{
		int ethPacketCount;
		int ipv4PacketCount;
		int ipv6PacketCount;
		int tcpPacketCount;
		int udpPacketCount;
		int dnsPacketCount;
		int httpPacketCount;
		int sslPacketCount;


        //initial
		void clear() { ethPacketCount = 0; ipv4PacketCount = 0; ipv6PacketCount = 0; tcpPacketCount = 0; udpPacketCount = 0; tcpPacketCount = 0; dnsPacketCount = 0; httpPacketCount = 0; sslPacketCount = 0; }

	/**
	* C'tor
	*/
		PacketStats() { clear(); }

	/**
	* Collect stats from a packet
	*/
		void consumePacket(pcpp::Packet& packet)
		{
			if (packet.isPacketOfType(pcpp::Ethernet))
				ethPacketCount++;
			if (packet.isPacketOfType(pcpp::IPv4))
				ipv4PacketCount++;
			if (packet.isPacketOfType(pcpp::IPv6))
				ipv6PacketCount++;
			if (packet.isPacketOfType(pcpp::TCP))
				tcpPacketCount++;
			if (packet.isPacketOfType(pcpp::UDP))
				udpPacketCount++;
			if (packet.isPacketOfType(pcpp::HTTP))
				httpPacketCount++;
			if (packet.isPacketOfType(pcpp::SSL))
				sslPacketCount++;
		}

	/**
	* Print stats to console
	*/
		void printToConsole()
		{
			printf("Ethernet packet count: %d\n", ethPacketCount);
			printf("IPv4 packet count:     %d\n", ipv4PacketCount);
			printf("IPv6 packet count:     %d\n", ipv6PacketCount);
			printf("TCP packet count:      %d\n", tcpPacketCount);
			printf("UDP packet count:      %d\n", udpPacketCount);
			printf("DNS packet count:      %d\n", dnsPacketCount);
			printf("HTTP packet count:     %d\n", httpPacketCount);
			printf("SSL packet count:      %d\n", sslPacketCount);
		}
	};

static void onPacketArrives(pcpp::RawPacket* packet,pcpp::PcapLiveDevice* dev,void* cookie){

		PacketStats* stats = (PacketStats*)cookie;

		pcpp::Packet parsedPacket(packet);

		stats->consumePacket(parsedPacket);
	}

static bool onPacketArrivesBlockingMode(pcpp::RawPacket* packet,pcpp::PcapLiveDevice* dev,void* cookie){
    PacketStats* stats = (PacketStats*)cookie;
    pcpp::Packet parsedPacket(packet);
    stats->consumePacket(parsedPacket);
    return false;
}

int main(int argc, char* argv[])
{
    //current network adapter
	string ip = "192.168.1.178";

    //GET THE ADAPTER
	pcpp::PcapLiveDevice* dev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(ip.c_str());
	printf("%s\n",dev->getName());

	if(!dev->open()){
		cout<<"Cannot open the device"<<endl;
	}

    //COUNT THE NUMBER OF PACKETS
	PacketStats stats;


    stats.clear();
    //Asynchronous packet capture using a callback function
//	dev->startCapture(onPacketArrives,&stats);

    //Asynchronous packet capture using a packet list
	pcpp::RawPacketVector packetVec;

    //START CAPTURE
	dev->startCapture(packetVec);
    //Synchronous packet capture using a callback function
//    dev->startCaptureBlockingMode(onPacketArrivesBlockingMode,&stats,10);

    //the time used for capture
	PCAP_SLEEP(20);

dev->stopCapture();

	cout<<"Result:"<<endl;

    pcpp::PcapFileWriterDevice pcapWriter("output.pcap",pcpp::LINKTYPE_ETHERNET);
	pcapWriter.open();

    pcapWriter.writePackets(packetVec);
    //count the packets
    for(pcpp::RawPacketVector::ConstVectorIterator iter = packetVec.begin();iter != packetVec.end();iter++){

		pcpp::Packet parsedPacket(*iter);

		stats.consumePacket(parsedPacket);

	}
    pcapWriter.close();
	stats.printToConsole();

		return 0;
}
