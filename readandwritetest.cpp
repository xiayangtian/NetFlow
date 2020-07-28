#include "stdlib.h"
#include "PcapFileDevice.h"
#include <iostream>
#include <stdio.h>
using namespace std;
int main(int argc,char* argv[]){

    pcpp::IFileReaderDevice* reader = pcpp::IFileReaderDevice::getReader("ip.pcap");
    if(reader == NULL){
        printf("cannot open");
        exit(1);
    }
    reader->open();
    pcpp::PcapFileWriterDevice pcapWriter("output.pcap",pcpp::LINKTYPE_ETHERNET);
    pcapWriter.open();

    pcpp::RawPacket rawPacket;
    while(reader->getNextPacket(rawPacket)){
        pcapWriter.writePacket(rawPacket);

    }
    pcap_stat stats;
    reader->getStatistics(stats);
    cout<<"success numbers:"<<stats.ps_recv<<"wrong numbers:"<<stats.ps_drop<<endl;
    pcapWriter.getStatistics(stats);
    printf("Written %d packets successfully to pcap writer and %d packets could not be written\n", stats.ps_recv, stats.ps_drop);


    reader->close();
    pcapWriter.close();
}
