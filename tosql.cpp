//reading the pcap file and insert it into mysql table
//tempss<<data;
//tempss>>temp;
//it is just for format data using the stream
#include<iostream>
#include<stdio.h>
#include<stdlib.h>
#include"netinet/in.h"
#include"Packet.h"
#include"EthLayer.h"
#include"IPv4Layer.h"
#include"IPv6Layer.h"
#include"TcpLayer.h"
#include"UdpLayer.h"
#include"HttpLayer.h"
#include"PcapFileDevice.h"
#include<arpa/inet.h>
#include"mysql.h"
#include<string>
#include<sstream>
#include<bitset>
#include<time.h>
#include<unistd.h>
using namespace std;
//just for test
string getProtocolTypeAsString(pcpp::ProtocolType protocolType){
    switch(protocolType){
        case pcpp::Ethernet:
            return "Ethernet";
        case pcpp::IPv4:
            return "IPv4";
        case pcpp::IPv6:
            return "IPv6";
        case pcpp::TCP:
            return "TCP";
        case pcpp::UDP:
            return "UDP";
        case pcpp::HTTPRequest:
        case pcpp::HTTPResponse:
            return "HTTP";
        default:
            return "Unknown";
    }
}
//just for test
string printTcpFlags(pcpp::TcpLayer* tcpLayer){
    string result = "";
    if (tcpLayer->getTcpHeader()->synFlag == 1)
		result += "SYN ";
	if (tcpLayer->getTcpHeader()->ackFlag == 1)
		result += "ACK ";
	if (tcpLayer->getTcpHeader()->pshFlag == 1)
		result += "PSH ";
	if (tcpLayer->getTcpHeader()->cwrFlag == 1)
		result += "CWR ";
	if (tcpLayer->getTcpHeader()->urgFlag == 1)
		result += "URG ";
	if (tcpLayer->getTcpHeader()->eceFlag == 1)
		result += "ECE ";
	if (tcpLayer->getTcpHeader()->rstFlag == 1)
		result += "RST ";
	if (tcpLayer->getTcpHeader()->finFlag == 1)
		result += "FIN ";

	return result;
}
unsigned short transfers(unsigned short a) {
	return ((a << 8) & 0xff00 | (a >> 8) & 0x00ff);
}
unsigned int transferi(unsigned int a) {
	int b = ((a << 16) & 0xffff0000 | (a >> 16) & 0x0000ffff);
	return ((b << 8) & 0xff000000 | (b >> 8) & 0x00ff0000 | (b << 8) & 0x0000ff00 | (b >> 8) & 0x000000ff);
}
//insert the data from pcap into mysql
int insert_to_sql(MYSQL* conn,pcpp::RawPacket rawPacket){
	string tempsql;
    string constsql = "insert into Raw_data(timestamp_h,timestamp_l,caplen,len,srcmac,dstmac,eth_type,is_ipv4,is_ipv6";
    string constipv4 = ",ipv4_hlen,ipv4_tos,ipv4_toslen,ipv4_id,ipv4_df,ipv4_mf,ipv4_offset,ipv4_ttl,ipv4_protocol,ipv4_checksum,ipv4_srcip,ipv4_dstip";
    string constipv6 = ",ipv6_traffic,ipv6_flowlb,ipv6_payload,ipv6_protocol,ipv6_hoplimit,ipv6_srcip,ipv6_dstip";
    string consttcp = ",is_tcp,is_udp,tcp_srcport,tcp_dstport,tcp_seqno,tcp_ackno,tcp_thlen,tcp_urg,tcp_ack,tcp_psh,tcp_rst,tcp_syn,tcp_fin,tcp_wnd_size,tcp_checksum,tcp_urgt_p";
    string constudp = ",is_tcp,is_udp,udp_srcport,udp_dstport,udp_len,udp_checksum";
    string constend = ") values('";
    string finalsql;
    stringstream tempss;
    string temp;
    //the data in pcapfile
    tempss<<rawPacket.getPacketTimeStamp().tv_sec;
    tempss>>temp;
    tempss.clear();
    tempsql+=temp+"','";
    tempss<<rawPacket.getPacketTimeStamp().tv_usec;
    tempss>>temp;
    tempsql+=temp+"','";
    tempss.clear();
    tempss<<rawPacket.getFrameLength();
    tempss>>temp;
    tempsql+=temp+"','";
    tempss.clear();
    tempss<<rawPacket.getRawDataLen();
    tempsql+=temp+"','";
    tempss.clear();
    pcpp::Packet parsedPacket(&rawPacket);

    //the data in ethernetLayer
    pcpp::EthLayer* ethernetLayer = parsedPacket.getLayerOfType<pcpp::EthLayer>();
    if (ethernetLayer == NULL){
        printf("cannot find Ethernet layer");
        exit(1);
    }

    tempss.clear();
    temp.erase();
    tempsql+=ethernetLayer->getSourceMac().toString();
    tempsql+=temp+"','";
    tempsql+=ethernetLayer->getDestMac().toString();
    tempsql+=temp+"','";
    tempss.clear();
    tempss.str("");
    tempss<<ntohs(ethernetLayer->getEthHeader()->etherType);
    tempss>>temp;
    tempsql+=temp+"','";

    int isipv4 = 0;
    int isipv6 = 0;
    int istcp = 0;
    int isudp = 0;
    int iptype = ethernetLayer->getEthHeader()->etherType;
    int tcptype = 0;
    //judge the type of IP
    if(iptype == 8){
        cout<<"IPv4"<<endl;
        isipv4 = 1;
    }
    if(iptype == 56710){
        cout<<"IPv6"<<endl;
        isipv6 = 1;
    }
    tempss.clear();
    tempss<<isipv4;
    tempss>>temp;
    tempsql+=temp+"','";
    tempss.clear();
    tempss<<isipv6;
    tempss>>temp;
    //tempsql+=temp+"','";
    //judge some protocol which do not use ip protocol ,like arp
    if(!isipv4&&!isipv6){
        tempsql+=temp+"')";
        finalsql = constsql+constend+tempsql;
        cout<<finalsql<<endl;
        mysql_query(conn,finalsql.c_str());
        return 1;
    }
    else{
        tempsql+=temp+"','";
    }
    //the data in ipv4Layer
    if(isipv4){
        pcpp::IPv4Layer* ipLayer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();
        tcptype = ipLayer->getIPv4Header()->protocol+0;
        tempss.clear();
        tempss.str("");
		tempss<<ipLayer->getHeaderLen();
		tempss>>temp;
		tempsql+=temp+"','";
		tempss.clear();
		tempss<<ipLayer->getIPv4Header()->typeOfService+0;
		tempss>>temp;
		tempsql+=temp+"','";
		tempss.clear();
		tempss<<transfers(ipLayer->getIPv4Header()->totalLength);
		tempss>>temp;
		tempsql+=temp+"','";
		tempss.clear();
		tempss<<ntohs(ipLayer->getIPv4Header()->ipId);
		tempss>>temp;
		tempsql+=temp+"','";
		tempss.clear();
		tempss<<!(ipLayer->isFragment());
		tempss>>temp;
		tempsql+=temp+"','";
		tempss.clear();
		tempss<<ipLayer->isLastFragment();
		tempss>>temp;
		tempsql+=temp+"','";
		tempss.clear();
		tempss<<ipLayer->getFragmentOffset();
		tempss>>temp;
		tempsql+=temp+"','";
		tempss.clear();
		tempss<<ipLayer->getIPv4Header()->timeToLive+0;
		tempss>>temp;
		tempsql+=temp+"','";
		tempss.clear();
		tempss<<ipLayer->getIPv4Header()->protocol+0;
		tempss>>temp;
		tempsql+=temp+"','";
		tempss.clear();
		tempss<<transfers(ipLayer->getIPv4Header()->headerChecksum);
		tempss>>temp;
		tempsql+=temp+"','";
		tempss.clear();
		tempss<<ipLayer->getSrcIpAddress().toString();
		tempss>>temp;
		tempsql+=temp+"','";
		tempss.clear();
		tempss<<ipLayer->getDstIpAddress().toString();
		tempss>>temp;
        //tempsql+=temp+"','";

    }
    //the data in ipv6Layer
    if(isipv6){
        pcpp::IPv6Layer* ipv6Layer = parsedPacket.getLayerOfType<pcpp::IPv6Layer>();
        tcptype = ipv6Layer->getIPv6Header()->nextHeader+0;
        tempss.clear();
		tempss<<ipv6Layer->getIPv6Header()->trafficClass+0;
		tempss>>temp;
		tempsql+=temp+"','";
		tempss.clear();
		tempss<<(ipv6Layer->getIPv6Header()->flowLabel[0]+0)*65536+(ipv6Layer->getIPv6Header()->flowLabel[1]+0)*256+(ipv6Layer->getIPv6Header()->flowLabel[2]+0)*16+(ipv6Layer->getIPv6Header()->flowLabel[3]+0);
		tempss>>temp;
		tempsql+=temp+"','";
		tempss.clear();
		tempss<<transfers(ipv6Layer->getIPv6Header()->payloadLength);
		tempss>>temp;
		tempsql+=temp+"','";
		tempss.clear();
		tempss<<ipv6Layer->getIPv6Header()->nextHeader+0;
		tempss>>temp;
		tempsql+=temp+"','";
		tempss.clear();
		tempss<<ipv6Layer->getIPv6Header()->hopLimit+0;
		tempss>>temp;
		tempsql+=temp+"','";
		tempss.clear();
		tempss<<ipv6Layer->getSrcIpAddress().toString();
		tempss>>temp;
		tempsql+=temp+"','";
		tempss.clear();
		tempss<<ipv6Layer->getDstIpAddress().toString();
		tempss>>temp;
        //tempsql+=temp+"','";

    }

    if(tcptype == 6){
        istcp = 1;
        cout<<"TCP"<<endl;
    }
    if(tcptype == 17){
        isudp = 1;
        cout<<"UDP"<<endl;
    }
    //judge some protocol which do not use the tcp or udp, like icmp
    if(!istcp&&!isudp){
        tempsql+=temp+"')";
        if(isipv4){
            finalsql = constsql+constipv4+constend+tempsql;
        }
        if(isipv6){
            finalsql = constsql+constipv6+constend+tempsql;
        }
        cout<<finalsql<<endl;
        mysql_query(conn,finalsql.c_str());
        return 1;
    }
    else{
        tempsql+=temp+"','";
    }
    tempss.clear();
    tempss<<istcp;
    tempss>>temp;
    tempsql+=temp+"','";
    tempss.clear();
    tempss<<isudp;
    tempss>>temp;
    tempsql+=temp+"','";
    if(istcp){
        pcpp::TcpLayer* tcpLayer = parsedPacket.getLayerOfType<pcpp::TcpLayer>();
        tempss.clear();
        tempss.str();

		tempss<<ntohs(tcpLayer->getTcpHeader()->portSrc);
		tempss>>temp;
		tempsql+=temp+"','";
		tempss.clear();
		tempss<<ntohs(tcpLayer->getTcpHeader()->portDst);
		tempss>>temp;
		tempsql+=temp+"','";


		tempss.clear();
		tempss<<transferi(tcpLayer->getTcpHeader()->sequenceNumber);
		tempss>>temp;
		tempsql+=temp+"','";
		tempss.clear();
		tempss<<transferi(tcpLayer->getTcpHeader()->ackNumber);
		tempss>>temp;
		tempsql+=temp+"','";
		tempss.clear();
		tempss<<tcpLayer->getHeaderLen();
		tempss>>temp;
		tempsql+=temp+"','";
		tempss.clear();
		tempss<<tcpLayer->getTcpHeader()->urgFlag;
		tempss>>temp;
		tempsql+=temp+"','";
		tempss.clear();
		tempss<<tcpLayer->getTcpHeader()->ackFlag;
		tempss>>temp;
		tempsql+=temp+"','";
		tempss.clear();
		tempss<<tcpLayer->getTcpHeader()->pshFlag;
		tempss>>temp;
		tempsql+=temp+"','";
		tempss.clear();
		tempss<<tcpLayer->getTcpHeader()->rstFlag;
		tempss>>temp;
		tempsql+=temp+"','";
		tempss.clear();
		tempss<<tcpLayer->getTcpHeader()->synFlag;
		tempss>>temp;
		tempsql+=temp+"','";
		tempss.clear();
		tempss<<tcpLayer->getTcpHeader()->finFlag;
		tempss>>temp;
		tempsql+=temp+"','";
		tempss.clear();
		tempss<<ntohs(tcpLayer->getTcpHeader()->windowSize);
		tempss>>temp;
		tempsql+=temp+"','";
		tempss.clear();
		tempss<<transfers(tcpLayer->getTcpHeader()->headerChecksum);
		tempss>>temp;
		tempsql+=temp+"','";
		tempss.clear();
		tempss<<tcpLayer->getTcpHeader()->urgentPointer;
		tempss>>temp;
		tempsql+=temp+"')";
        if(isipv4)
            finalsql = constsql+constipv4+consttcp+constend+tempsql;
        else
            finalsql = constsql+constipv6+consttcp+constend+tempsql;
        cout<<finalsql<<endl;
        mysql_query(conn,finalsql.c_str());
        return 1;

    }
    if(isudp){

        pcpp::UdpLayer* udpLayer = parsedPacket.getLayerOfType<pcpp::UdpLayer>();
        tempss.clear();
		tempss.str();
		tempss<<transfers(udpLayer->getUdpHeader()->portSrc);
		tempss>>temp;
		tempsql+=temp+"','";
		tempss.clear();
		tempss<<transfers(udpLayer->getUdpHeader()->portDst);
		tempss>>temp;
		tempsql+=temp+"','";
		tempss.clear();
		tempss<<transfers(udpLayer->getUdpHeader()->length);
		tempss>>temp;
		tempsql+=temp+"','";
		tempss.clear();
		tempss<<transfers(udpLayer->getUdpHeader()->headerChecksum);
		tempss>>temp;
		tempsql+=temp+"')";
        if(isipv4)
            finalsql = constsql+constipv4+constudp+constend+tempsql;
        else
            finalsql = constsql+constipv6+constudp+constend+tempsql;
        cout<<finalsql<<endl;
        mysql_query(conn,finalsql.c_str());
        return 1;
    }
    return 0;
}

int main(int argc,char* argv[]){
    MYSQL *conn;
    MYSQL_RES *result;
    MYSQL_ROW row;
    MYSQL_FIELD *field;
    int num_fields;
    int i;
    conn = mysql_init(NULL);
    if(mysql_real_connect(conn,"localhost","root","123456Xia.",NULL,3306,NULL,0));
    //if(mysql_real_connect(conn,"192.168.1.167","root","416dbpwd123",NULL,3306,NULL,0));
    mysql_query(conn,"create database netflow");
    mysql_query(conn,"use netflow");
    mysql_query(conn,"create table Raw_data(id int auto_increment primary key,timestamp_h varchar(45) default 0,timestamp_l varchar(45) default 0,caplen int default 0,\
        len int default 0,srcmac varchar(45) default 0,dstmac varchar(45) default 0,eth_type int default 0,is_ipv4 tinyint default 0,is_ipv6 tinyint default 0,\
        ipv4_hlen int default 0,ipv4_tos int default 0,ipv4_toslen int default 0,ipv4_id int default 0,ipv4_df tinyint default 0,ipv4_mf tinyint default 0,ipv4_offset int default 0,\
        ipv4_ttl int default 0,ipv4_protocol int default 0,ipv4_checksum int default 0,ipv4_srcip varchar(45) default 0,ipv4_dstip varchar(45) default 0,ipv6_traffic int default 0,\
        ipv6_flowlb int default 0,ipv6_payload int default 0,ipv6_protocol int default 0,ipv6_hoplimit int default 0,ipv6_srcip varchar(45) default 0,ipv6_dstip varchar(45) default 0,\
        is_tcp tinyint default 0,is_udp tinyint default 0,tcp_srcport int default 0,tcp_dstport int default 0,tcp_seqno varchar(45) default 0,tcp_ackno varchar(45) default 0,\
        tcp_thlen int default 0,tcp_urg tinyint default 0,tcp_ack tinyint default 0,tcp_psh tinyint default 0,tcp_rst tinyint default 0,tcp_syn tinyint default 0,\
        tcp_fin tinyint default 0,tcp_wnd_size int default 0,tcp_checksum int default 0,tcp_urgt_p int default 0,udp_srcport int default 0,udp_dstport int default 0,\
        udp_len int default 0,udp_checksum int default 0)");
    pcpp::IFileReaderDevice* reader = pcpp::IFileReaderDevice::getReader("http.pcap");
    reader->open();
    pcpp::RawPacket rawPacket;
    int n=1;
    int temp;
    bool hasnext = true;
    while(hasnext){
        hasnext = reader->getNextPacket(rawPacket);
        cout<<n++<<endl;
        if(hasnext)temp = insert_to_sql(conn,rawPacket);

    }
    reader->close();
    //insert_to_sql(conn,rawPacket);
    //show the result
    mysql_query(conn,"select * from Raw_data");
    result = mysql_store_result(conn);
    num_fields = mysql_num_fields(result);
    while(row = mysql_fetch_row(result)){
        for(int i=0;i<num_fields;i++){
            if(i==0){
                while(field = mysql_fetch_field(result)){
                    //printf("%s  ",field->name);
                }
                printf("\n");
            }
            printf("%s  ",row[i]?row[i]:"NULL");
        }
    }
    printf("\n");
    mysql_free_result(result);
   // mysql_query(conn,"delete from Raw_data");
    mysql_close(conn);
}
