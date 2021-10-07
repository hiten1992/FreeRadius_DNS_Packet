#ifndef _DNS_UDP_H_
#define _DNS_UDP_H_

#include <errno.h>
#include <netdb.h>
#include <stdio.h>				//For standard things
#include <stdlib.h>				//malloc
#include <string.h>				//strlen
#include <unistd.h>
#include <time.h>
#include <netinet/ip_icmp.h>	//Provides declarations for icmp header
#include <netinet/udp.h>		//Provides declarations for udp header
#include <netinet/tcp.h>		//Provides declarations for tcp header
#include <netinet/ip.h>			//Provides declarations for ip header
#include <netinet/if_ether.h>	//For ETH_P_ALL
#include <net/ethernet.h>		//For ether_header
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/types.h>

#define UC	unsigned char
#define UI	unsigned int
#define US	unsigned short
#define UL	unsigned long
#define CC	const char

#define PORT 					1813    // 2123 for GTP
#define SAVE_DATA 				0
#define UDP 					1		// UDP protocol
#define PROTOCOL                'R'

#define RAD_ATTR_MAX 			200
#define UNS_ATTR_MAX 			181
#define USERTYPE_MAX	 		11
#define FRAME_MAX		 		6
#define FRAME_ROUTE_MAX		 	4
#define FRAME_COMP_MAX		 	4
#define LOGIN_SERV_MAX		 	8
#define ACCT_STATUS_MAX		 	5
#define ACCT_AUTH_MAX			3
#define TERMINATION_MAX		 	2
#define NAS_MAX				 	16
#define ACCT_TERM_MAX			18
#define NON_PROTO_AUTH_MAX		7
#define SERVER_CONF_MAX			2

#define CAPACITY 				50000 // Size of the Hash Table

#define REV(x) ( (x & 0x0F)<<4 | (x & 0xF0)>>4 )

struct radius
{
	char attribute[50];
	int value;
	char type[20];
};

struct User_Types
{
	char attribute[50];
	char Type_name[50];
	int value;
};

struct Framed_Protocol
{
	char attribute[50];
	char Type_name[50];
	int value;
};

struct Framed_Routing
{
	char attribute[50];
	char Type_name[50];
	int value;
};

struct Framed_Compression
{
	char attribute[50];
	char Type_name[50];
	int value;
};

struct Login_Services
{
	char attribute[50];
	char Type_name[50];
	int value;
};

struct Acct_Status
{
	char attribute[50];
	char Type_name[50];
	int value;
};

struct Acct_Authentic
{
	char attribute[50];
	char Type_name[50];
	int value;
};

struct Termination
{
	char attribute[50];
	char Type_name[50];
	int value;
};

struct NAS_Port
{
	char attribute[50];
	char Type_name[50];
	int value;
};

struct Acct_Terminate
{
	char attribute[50];
	char Type_name[50];
	int value;
};

struct Non_Protocol_Auth_Type
{
	char attribute[50];
	char Type_name[50];
	int value;
};

struct Server_Config
{
	char attribute[50];
	char Type_name[50];
	int value;
};

typedef struct Ht_item Ht_item;
 
// Define the Hash Table Item here
struct Ht_item
{
    char* key;
    char* value;
};
 
typedef struct HashTable HashTable;
 
// Define the Hash Table here
struct HashTable
{
    // Contains an array of pointers to items
    Ht_item** items;
    int size;
    int count;
};

typedef union uwb {
	unsigned w;
	unsigned char b[4];
} MD5union;

typedef unsigned DigestArray[4];

typedef unsigned(*DgstFctn)(unsigned a[]);

void 			bytes2md5						(const char *data, int len, char *md5buf);
char 	* 		IPAddressToString				(int ip, UC *Ip_Address);
void 			char2hex						(UC *source,UC *target,US len);
void 			Convert_Timestamp_To_DateTime	(time_t rawtime , char *output);
void 			send4Debug						(UC flg,UC* buf, UI len);
long long int 	convertHexTodec					(UC *str);
void 			ProcessPacket					(UC*Buffer , int);
void 			print_ethernet_header			(UC *Buffer, int Size);
void 			print_ip_header					(UC*Buffer , int);
void 			print_tcp_packet				(UC *Buffer , int );
void 			Fetch_Radius_Attributes			(UC *str, int len);
void 			Save_data_Into_Mysql			(void);
void 			finish_with_error				(MYSQL *con);
void 			print_udp_packet				(UC *Buffer , int );
void 			print_icmp_packet				(UC*Buffer , int );
void 			PrintData 						(UC* , int);
unsigned long 	hash_function					(char* str);
void 			print_table						(HashTable* table);
void 			print_search					(HashTable* table, char* key , UC* val);
UC	* 			ht_search						(HashTable* table, char* key);
void 			ht_insert						(HashTable* table, char* key, char* value);
void 			handle_collision				(HashTable* table, unsigned long index, Ht_item* item);
void 			free_table						(HashTable* table);
void 			free_item						(Ht_item* item);
HashTable	* 	create_table					(int size);
Ht_item		* 	create_item						(char* key, char* value);
int 			Check_session_ID				(UC * acctsessionid , MYSQL *con);
void 			delete_create_table				(MYSQL *con);
unsigned        func0                           (unsigned abcd[]);
unsigned        func1                           (unsigned abcd[]);
unsigned        func2                           (unsigned abcd[]);
unsigned        func3                           (unsigned abcd[]);
unsigned    *   calctable                       (unsigned *k);
unsigned        rol                             (unsigned r, short N);
unsigned    *   Algorithms_Hash_MD5             (const char *msg, int mlen);
void            GetMD5String                    (const char *msg, int mlen,unsigned char * acctuniqueid);

void            Fetch_GTP_Data                  (UC *str , int len);
void            fetch_imsi                      (UC * temp , UC * imsi , int len);
void            decToBinary                     (int n , char *buf);
int             binaryToDecimal                 (int n);

#endif
