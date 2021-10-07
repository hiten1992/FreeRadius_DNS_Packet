#include<stdio.h> //For standard things
#include<stdlib.h>    //malloc
#include<string.h>    //memset
#include<netinet/ip_icmp.h>   //Provides declarations for icmp header
#include<netinet/udp.h>   //Provides declarations for udp header
#include<netinet/tcp.h>   //Provides declarations for tcp header
#include<netinet/ip.h>    //Provides declarations for ip header
#include<sys/socket.h>
#include<arpa/inet.h>
#include<net/ethernet.h>	//For ether_header

#define PORT 9997

void print_udp_packet(unsigned char*, int);
void ProcessPacket(unsigned char*, int);
void PrintData (unsigned char* , int);

int sockt;
int i,j;

struct sockaddr_in source,dest; 

void ProcessPacket(unsigned char* buffer, int size)
{
	struct iphdr *iph;
	
	//Get the IP Header part of this packet , excluding the ethernet header
	iph = (struct iphdr*)buffer;
	
	printf("\niph->protocol : %d\n",iph->protocol); fflush(stdout);
	
    switch (iph->protocol) //Check the Protocol and do accordingly...
	{
		case 17: //UDP Protocol
				print_udp_packet(buffer , size);
				break;
		default: //UDP Protocol
				print_udp_packet(buffer , size);
				break;
	}

}

void print_ethernet_header(unsigned char *Buffer, int Size)
{
	struct ethhdr *eth = (struct ethhdr *)Buffer;
	
	printf("\n");
	printf("Ethernet Header\n");
	printf("   |-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5] );
	printf("   |-Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5] );
	printf("   |-Protocol            : %u \n",(unsigned short)eth->h_proto);
}

void print_ip_header(unsigned char* Buffer, int Size)
{
	unsigned short iphdrlen;
	struct iphdr *iph;
	
	iph = (struct iphdr*)Buffer;
	
	print_ethernet_header(Buffer , Size);
	
	iphdrlen =iph->ihl*4;
	
	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;
	
	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;
	
	printf("\n");
	printf("IP Header\n");
	printf("   |-IP Version        : %d\n",(unsigned int)iph->version);
	printf("   |-IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
	printf("   |-Type Of Service   : %d\n",(unsigned int)iph->tos);
	printf("   |-IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(iph->tot_len));
	printf("   |-Identification    : %d\n",ntohs(iph->id));
	printf("   |-TTL      : %d\n",(unsigned int)iph->ttl);
	printf("   |-Protocol : %d\n",(unsigned int)iph->protocol);
	printf("   |-Checksum : %d\n",ntohs(iph->check));
	printf("   |-Source IP        : %s\n" , inet_ntoa(source.sin_addr) );
	printf("   |-Destination IP   : %s\n" , inet_ntoa(dest.sin_addr) );
}

void print_udp_packet(unsigned char *Buffer , int Size)
{
    unsigned short iphdrlen;

    struct iphdr *iph = (struct iphdr *)Buffer;
    iphdrlen = iph->ihl*4;
    
    struct udphdr *udph = (struct udphdr*)(Buffer + iphdrlen);
    
    //~ print_ip_header(Buffer,size);
    
    printf("\n\nData Payload\n");  
    PrintData(Buffer + iphdrlen + sizeof udph ,( Size - sizeof udph - iph->ihl * 4 ));
	
    printf("\n###########################################################\n\n");
}

void PrintData (unsigned char* data , int size)
{
    for(i=0 ; i < size ; i++)
    {
        if( i!=0 && i%16==0)   //if one line of hex printing is complete...
        {
            printf("         ");
            for(j=i-16 ; j<i ; j++)
            {
                if(data[j]>=32 && data[j]<=128)
                    printf("%c",(unsigned char)data[j]); //if its a number or alphabet

                else printf("."); //otherwise print a dot
            }
            printf("\n");
        } 

        if(i%16==0) printf("   ");
            printf(" %02X",(unsigned int)data[i]);

        if( i==size-1)  //print the last spaces
        {
            for(j=0;j<15-i%16;j++) printf("   "); //extra spaces

            printf("   ");

            for(j=i-i%16 ; j<=i ; j++)
            {
                if(data[j]>=32 && data[j]<=128) printf("%c",(unsigned char)data[j]);
                else printf(".");
            }
            printf("\n");
        }
    }
}

int main()
{
	int saddr_size,data_size;
	struct sockaddr_in saddr;
	struct sockaddr_in daddr;

	//struct in_addr in;
	unsigned char *buffer = (unsigned char *)malloc(65536);
	
	
	printf("Starting...\n"); fflush(stdout);
	
	//Create a socket
	//~ sockt = socket(AF_INET , SOCK_RAW , IPPROTO_UDP);
	sockt = socket(AF_INET ,SOCK_DGRAM ,IPPROTO_UDP);
	if(sockt < 0)
	{
		printf("Socket Error\n"); fflush(stdout);
		return 1;
	}
	memset((char *)&daddr,0,sizeof(daddr));
	
    //prepare the sockaddr_in structure
    daddr.sin_family = AF_INET;
    daddr.sin_addr.s_addr = htonl(INADDR_ANY);
    daddr.sin_port = htons(PORT);

    //Bind
    if(bind(sockt,(struct sockaddr *)&daddr, sizeof(daddr))<0)
    {
      printf("bind failed"); fflush(stdout);
      return 1;
    }
    printf("bind done\n"); fflush(stdout);

    while(1)
    {
		saddr_size = sizeof saddr;
		
		//Receive a packet
		data_size = recvfrom(sockt , buffer ,65536 , 0 , (struct sockaddr*) &saddr , (socklen_t*)&saddr_size);
		if(data_size <0)
		{
		  printf("\nPackets not received\n"); fflush(stdout);
		  return 1;
		}
		
		print_udp_packet(buffer ,data_size);
    }
    close(sockt);
    printf("Finished");
    return 0;
}
