/**
 * 	To run the application without root permission, run command - "sudo setcap cap_net_admin,cap_net_raw=eip <executable_name>"
 * 
 * 	https://stackoverflow.com/questions/3998569/how-to-bind-raw-socket-to-specific-interface
 * 	https://www.binarytides.com/raw-udp-sockets-c-linux/
 * 	https://github.com/FreeRADIUS/freeradius-client/blob/master/etc/dictionary
 * 	https://fossies.org/linux/wireshark/radius/dictionary.unisphere
 * 	https://www.opensourceforu.com/2015/03/a-guide-to-using-raw-sockets/
 * 	https://linuxhint.com/send_receive_udp_packets_linux_cli/
 * 	https://linuxhint.com/send_receive_udp_python/
 * 
 * 	sudo tcpdump -i lo udp port 1813 -v
 * 
 *  To save data in pcap file using tcpdump command for wireshark, use the following command-->>
 *         
 *          "sudo tcpdump -w rad.pcap -i lo udp port 1813"
 * 
 * 	pip install pyrad
 * 
 *	https://hpd.gasmi.net/?data=450000524236000040113A637F0000017F00000191620715003EFE51042F00361137911056F1338508D0BA1270C197122C226163323033653463323238616338353762343164383661336233623735393764&force=ipv4
 * 
 * 	https://www.elvidence.com.au/understanding-time-stamps-in-packet-capture-data-pcap-files/
 * 	
 * 	https://www.geeksforgeeks.org/convert-unix-timestamp-to-dd-mm-yyyy-hhmmss-format/
 * 
 * 	https://www.journaldev.com/35238/hash-table-in-c-plus-plus
 * 
 * 	///////////////////// MYSQL /////////////////////////////////////////
 * 
 * 	sudo apt install libmysqlclient-dev
 * 	sudo apt install mysql-server
 * 	sudo mysql_secure_installation
 * 
 * 	CREATE USER 'root'@'localhost' IDENTIFIED BY 'testing@123';
 * 	DROP USER 'root'@'localhost';
 * 	delete from user where user='root'and host='localhost';
 * 	grant all privileges on `mydb` to 'root'@'localhost';
 * 	SHOW DATABASES;
 * 	DESCRIBE <table_name>;
 * 	select * from <table_name>;		// to show table column data
 * 	delete from radacct;			// to delete all column data
 * 	drop table <table_name>
 * 	drop database <database_name>
 * 	select <column_name> table <table_name>		// to fetch particular column data
 * 
 * 	https://www.a2hosting.in/kb/developer-corner/mysql/managing-mysql-databases-and-users-from-the-command-line#:~:text=Replace%20username%20with%20the%20user,grants%20the%20user%20all%20permissions.
	https://www.informit.com/articles/article.aspx?p=482319
 * 	http://g2pc1.bu.edu/~qzpeng/manual/MySQL%20Commands.htm
 * 
	// To uninstall mysql from laptop-->>
	//	1. sudo systemctl stop mysql
	//	2. sudo apt-get purge mysql-server mysql-client mysql-common mysql-server-core-* mysql-client-core-*
	//	3. sudo rm -rf /etc/mysql /var/lib/mysql
	//	4. sudo apt autoremove
	//	5. sudo apt autoclean
 * 
 *  /////////////////// Install Openssl in Ubuntu //////////////////////////////////////////////////
 *  sudo apt-get install libssl-dev
 *  
 *  /////////////////// Install Openssl in Centos ////////////////////////////////////////////////// 
 *  sudo yum install openssl-devel
 *  
 *  yum install make gcc perl pcre-devel zlib-devel
 *  
 *  wget https://ftp.openssl.org/source/old/1.1.1/openssl-1.1.1.tar.gz
 *  tar xvf openssl-1.1.1.tar.gz
 *  cd openssl-1.1.1/
 *  ./config --prefix=/usr --openssldir=/etc/ssl --libdir=lib no-shared zlib-dynamic
 *  make
 *  make test
 *  sudo make install
 *  export LD_LIBRARY_PATH=/usr/local/lib:/usr/local/lib64
 *  echo "export LD_LIBRARY_PATH=/usr/local/lib:/usr/local/lib64" >> ~/.bashrc
 * 
 *  
 *  ////////////////////////////////////////////////////////////////////////////////////////////////
 *  
 *  /////////////////// Install Mysql in Centos ////////////////////////////////////////////////// 
 *  sudo yum install mysql-devel
 *  
 *  ////////////////////////////// Set mysql database in Centos ////////////////////////////////////////////
 *  // For Reference - https://www.mysqltutorial.org/install-mysql-centos/
 *  //    1.  rpm -Uvh https://repo.mysql.com/mysql80-community-release-el7-3.noarch.rpm
 *  //    2.  sed -i 's/enabled=1/enabled=0/' /etc/yum.repos.d/mysql-community.repo
 *  //    3.  yum --enablerepo=mysql80-community install mysql-community-server
 *  //    4.  service mysqld start
 *  //    5.  grep "A temporary password" /var/log/mysqld.log
 *  //    6.  mysql_secure_installation
 *  //
 *  //    Then, run command - sudo mysql -p and then enter the password you created to login in the database
 *  ////////////////////////////////////////////////////////////////////////////////////////////////
 *  
 *  
 * 	Other sockets like stream sockets and data gram sockets receive data from the 
 * 	transport layer that contains no headers but only the payload.
 * 	This means that there is no information about the source IP address and MAC address.
 * 	If applications running on the same machine or on different machines are 
 * 	communicating, then they are only exchanging data.
 * 	
 * 	The purpose of a raw socket is absolutely different.
 * 	A raw socket allows an application to directly access lower level protocols, 
 * 	which means a raw socket receives un-extracted packets (see Figure 2).
 * 	There is no need to provide the port and IP address to a raw socket, 
 * 	unlike in the case of stream and datagram sockets.
 */
#include <errno.h>
#include <netdb.h>
#include <stdio.h>				//For standard things
#include <stdlib.h>				//malloc
#include <string.h>				//strlen
#include <unistd.h>
#include <math.h>
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

#include <openssl/evp.h>		//For md5 functions

#include <mysql.h>				// For Mysql

#include "dns_udp.h"

FILE *logfile=NULL;

struct sockaddr_in source;
struct sockaddr_in dest;

int tcp		=	0;
int udp		=	0;
int icmp	=	0;
int others	=	0;
int igmp	=	0;
int total	=	0;

HashTable* ht;

struct radius radius_attr[RAD_ATTR_MAX] = 
			{
				{"User-Name"				,	1		,	"string"	},
				{"Password"					,	2		,	"string"    },
				{"CHAP-Password"			,	3		,	"string"    },
				{"NAS-IP-Address"			,	4		,	"ipaddr"    },
				{"NAS-Port"					,	5		,	"integer"   },
				{"Service-Type"				,	6		,	"integer"   },
				{"Framed-Protocol"			,	7		,	"integer"   },
				{"Framed-IP-Address"		,	8		,	"ipaddr"    },
				{"Framed-IP-Netmask"		,	9		,	"ipaddr"    },
				{"Framed-Routing"			,	10		,	"integer"   },
				{"Filter-Id"				,	11		,	"string"    },
				{"Framed-MTU"				,	12		,	"integer"   },
				{"Framed-Compression"		,	13		,	"integer"   },
				{"Login-IP-Host"			,	14		,	"ipaddr"    },
				{"Login-Service"			,	15		,	"integer"   },
				{"Login-TCP-Port"			,	16		,	"integer"   },
				{"Reply-Message"			,	18		,	"string"    },
				{"Callback-Number"			,	19		,	"string"    },
				{"Callback-Id"				,	20		,	"string"    },
				{"Framed-Route"				,	22		,	"string"    },
				{"Framed-IPX-Network"		,	23		,	"ipaddr"    },
				{"State"					,	24		,	"string"    },
				{"Class"					,	25		,	"string"    },
				{"Vendor-Specific"			,	26		,	"string"    },
				{"Session-Timeout"			,	27		,	"integer"   },
				{"Idle-Timeout"				,	28		,	"integer"   },
				{"Termination-Action"		,	29		,	"integer"   },
				{"Called-Station-Id"		,	30		,	"string"    },
				{"Calling-Station-Id"		,	31		,	"string"    },
				{"NAS-Identifier"			,	32		,	"string"    },
				{"Proxy-State"				,	33		,	"string"    },
				{"Login-LAT-Service"		,	34		,	"string"    },
				{"Login-LAT-Node"			,	35		,	"string"    },
				{"Login-LAT-Group"			,	36		,	"string"    },
				{"Framed-AppleTalk-Link"	,	37		,	"integer"   },
				{"Framed-AppleTalk-Network"	,	38		,	"integer"   },
				{"Framed-AppleTalk-Zone"	,	39		,	"string"    },
				{"Acct-Status-Type"			,	40		,	"integer"   },
				{"Acct-Delay-Time"			,	41		,	"integer"   },
				{"Acct-Input-Octets"		,	42		,	"integer"   },
				{"Acct-Output-Octets"		,	43		,	"integer"   },
				{"Acct-Session-Id"			,	44		,	"string"    },
				{"Acct-Authentic"			,	45		,	"integer"   },
				{"Acct-Session-Time"		,	46		,	"integer"   },
				{"Acct-Input-Packets"		,	47		,	"integer"   },
				{"Acct-Output-Packets"		,	48		,	"integer"   },
				{"Acct-Terminate-Cause"		,	49		,	"integer"   },
				{"Acct-Multi-Session-Id"	,	50		,	"string"    },
				{"Acct-Link-Count"			,	51		,	"integer"   },
				{"Acct-Input-Gigawords"		,	52		,	"integer"   },
				{"Acct-Output-Gigawords"	,	53		,	"integer"   },
				{"Event-Timestamp"			,	55		,	"integer"   },
				{"Egress-VLANID"			,	56		,	"string"    },
				{"Ingress-Filters"			,	57		,	"integer"   },
				{"Egress-VLAN-Name"			,	58		,	"string"    },
				{"User-Priority-Table"		,	59		,	"string"    },
				{"CHAP-Challenge"			,	60		,	"string"    },
				{"NAS-Port-Type"			,	61		,	"integer"   },
				{"Port-Limit"				,	62		,	"integer"   },
				{"Login-LAT-Port"			,	63		,	"integer"   },
				{"Tunnel-Type"				,	64		,	"string"    },
				{"Tunnel-Medium-Type" 		,	65		,	"string"    },
				{"Tunnel-Client-Endpoint"	,	66		,	"string"    },
				{"Tunnel-Server-Endpoint"	,	67		,	"string"    },
				{"Acct-Tunnel-Connection"	,	68		,	"string"    },
				{"Tunnel-Password"			,	69		,	"string"    },
				{"ARAP-Password" 			,	70		,	"string"    },
				{"ARAP-Features" 			,	71		,	"string"    },
				{"ARAP-Zone-Access"			,	72		,	"integer"   },
				{"ARAP-Security"			,	73		,	"integer"   },
				{"ARAP-Security-Data"		,	74		,	"string"    },
				{"Password-Retry"			,	75		,	"integer"   },
				{"Prompt"					,	76		,	"integer"   },
				{"Connect-Info"				,	77		,	"string"    },
				{"Configuration-Token"		,	78		,	"string"    },
				{"EAP-Message"				,	79		,	"string"    },
				{"Message-Authenticator"	,	80		,	"string"    },
				{"Tunnel-Private-Group-ID"	,	81		,	"string"    },
				{"Tunnel-Assignment-ID"		,	82		,	"string"    },
				{"Tunnel-Preference"		,	83		,	"string"    },
				{"ARAP-Challenge-Response"	,	84		,	"string"    },
				{"Acct-Interim-Interval"	,	85		,	"integer"   },
				{"Acct-Tunnel-Packets-Lost"	,	86		,	"integer"   },
				{"NAS-Port-Id"				,	87		,	"string"    },
				{"Framed-Pool"				,	88		,	"string"    },
				{"Chargeable-User-Identity"	,	89		,	"string"    },
				{"Tunnel-Client-Auth-ID"	,	90		,	"string"    },
				{"Tunnel-Server-Auth-ID"	,	91		,	"string"    },
				{"NAS-Filter-Rule"			,	92		,	"string"    },
				{"Originating-Line-Info"	,	94		,	"string"    },
				{"NAS-IPv6-Address"			,	95		,	"string"    },
				{"Framed-Interface-Id"		,	96		,	"string"    },
				{"Framed-IPv6-Prefix"		,	97		,	"ipv6prefix"},
				{"Login-IPv6-Host"			,	98		,	"string"    },
				{"Framed-IPv6-Route"		,	99		,	"string"    },
				{"Framed-IPv6-Pool"			,	100		,	"string"    },
				{"Error-Cause"				,	101		,	"integer"   },
				{"EAP-Key-Name"				,	102		,	"string"	},
				{"Framed-IPv6-Address"		,	168		,	"ipv6addr"	},
				{"Delegated-IPv6-Prefix"	,	123		,	"ipv6prefix"},
				{"DNS-Server-IPv6-Address"	,	169		,	"ipv6addr"	},
				{"Route-IPv6-Information"	,	170		,	"ipv6prefix"},
				{"Huntgroup-Name"			,	221		,	"string"	},
				{"User-Category"			,	1029	,	"string"	},
				{"Group-Name"				,	1030	,	"string"	},
				{"Simultaneous-Use"			,	1034	,	"integer"	},
				{"Strip-User-Name"			,	1035	,	"integer"	},
				{"Fall-Through"				,	1036	,	"integer"	},
				{"Add-Port-To-IP-Address"	,	1037	,	"integer"	},
				{"Exec-Program"				,	1038	,	"string"	},
				{"Exec-Program-Wait"		,	1039	,	"string"	},
				{"Hint"						,	1040	,	"string"	},
				{"Expiration"				,	21		,	"date"		},
				{"Auth-Type"				,	1000	,	"integer"	},
				{"Menu"						,	1001	,	"string"	},
				{"Termination-Menu"			,	1002	,	"string"	},
				{"Prefix"					,	1003	,	"string"	},
				{"Suffix"					,	1004	,	"string"	},
				{"Group"					,	1005	,	"string"	},
				{"Crypt-Password"			,	1006	,	"string"	},
				{"Connect-Rate"				,	1007	,	"integer"	},
				{"Acct-Unique-Session-Id"	,	1051	,	"string"	}
			 };

struct User_Types User_Types_Values[USERTYPE_MAX] = 
			{
				{"Service-Type"	,	"Login-User"				,	1	},
				{"Service-Type"	,	"Framed-User"				,	2	},
				{"Service-Type"	,	"Callback-Login-User"		,	3	},
				{"Service-Type"	,	"Callback-Framed-User"		,	4	},
				{"Service-Type"	,	"Outbound-User"				,	5	},
				{"Service-Type"	,	"Administrative-User"		,	6	},
				{"Service-Type"	,	"NAS-Prompt-User"			,	7	},
				{"Service-Type"	,	"Authenticate-Only"			,	8	},
				{"Service-Type"	,	"Callback-NAS-Prompt"		,	9	},
				{"Service-Type"	,	"Call-Check"				,	10	},
				{"Service-Type"	,	"Callback-Administrative"	,	11	}
			};

struct Framed_Protocol Framed_Protocol_Values[FRAME_MAX] = 
			{
				{"Framed-Protocol"	,	"PPP"				,	1	},
				{"Framed-Protocol"	,	"SLIP"				,	2	},
				{"Framed-Protocol"	,	"ARAP"				,	3	},
				{"Framed-Protocol"	,	"GANDALF-SLMLP"		,	4	},
				{"Framed-Protocol"	,	"XYLOGICS-IPX-SLIP"	,	5	},
				{"Framed-Protocol"	,	"X75"				,	6	}
			};

struct Framed_Routing Framed_Routing_Values[FRAME_ROUTE_MAX] = 
			{
				{"Framed-Routing"	,	"None"				,	0	},
				{"Framed-Routing"	,	"Broadcast"			,	1	},
				{"Framed-Routing"	,	"Listen"			,	2	},
				{"Framed-Routing"	,	"Broadcast-Listen"	,	3	}
			};

struct Framed_Compression Framed_Compression_Values[FRAME_COMP_MAX] = 
			{
				{"Framed-Compression"	,	"None"					,	0	},
				{"Framed-Compression"	,	"Van-Jacobson-TCP-IP"	,	1	},
				{"Framed-Compression"	,	"IPX-Header"			,	2	},
				{"Framed-Compression"	,	"Stac-LZS"				,	3	}
			};

struct Login_Services Login_Services_Values[LOGIN_SERV_MAX] = 
			{
				{"Login-Service"	,	"Telnet"			,	0	},
				{"Login-Service"	,	"Rlogin"			,	1	},
				{"Login-Service"	,	"TCP-Clear"			,	2	},
				{"Login-Service"	,	"PortMaster"		,	3	},
				{"Login-Service"	,	"LAT"				,	4	},
				{"Login-Service"	,	"X.25-PAD"			,	5	},
				{"Login-Service"	,	"X.25-T3POS"		,	6	},
				{"Login-Service"	,	"TCP-Clear-Quiet"	,	8	}
			};

struct Acct_Status Acct_Status_Values[ACCT_STATUS_MAX] = 
			{
				{"Acct-Status-Type"	,	"Start"				,	1	},
				{"Acct-Status-Type"	,	"Stop"				,	2	},
				{"Acct-Status-Type"	,	"Alive"				,	3	},
				{"Acct-Status-Type"	,	"Accounting-On"		,	7	},
				{"Acct-Status-Type"	,	"Accounting-Off"	,	8	}
			};

struct Acct_Authentic Acct_Authentic_Values[ACCT_AUTH_MAX] = 
			{
				{"Acct-Authentic"	,	"RADIUS"	,	1	},
				{"Acct-Authentic"	,	"Local"		,	2	},
				{"Acct-Authentic"	,	"Remote"	,	3	}
			};

struct Termination Termination_Values[TERMINATION_MAX] = 
			{
				{"Termiantion-Action"	,	"Default"			,	1	},
				{"Termiantion-Action"	,	"RADIUS-Request"	,	2	}
			};

struct NAS_Port NAS_Port_Values[NAS_MAX] = 
			{
				{"NAS-Port-Type"	,	"Async"					,	0	},
				{"NAS-Port-Type"	,	"Sync"					,	1	},
				{"NAS-Port-Type"	,	"ISDN"					,	2	},
				{"NAS-Port-Type"	,	"ISDN-V120"				,	3	},
				{"NAS-Port-Type"	,	"ISDN-V110"				,	4	},
				{"NAS-Port-Type"	,	"Virtual"				,	5	},
				{"NAS-Port-Type"	,	"PIAFS"					,	6	},
				{"NAS-Port-Type"	,	"HDLC-Clear-Channel"	,	7	},
				{"NAS-Port-Type"	,	"X.25"					,	8	},
				{"NAS-Port-Type"	,	"X.75"					,	9	},
				{"NAS-Port-Type"	,	"G.3-Fax"				,	10	},
				{"NAS-Port-Type"	,	"SDSL"					,	11	},
				{"NAS-Port-Type"	,	"ADSL-CAP"				,	12	},
				{"NAS-Port-Type"	,	"ADSL-DMT"				,	13	},
				{"NAS-Port-Type"	,	"IDSL"					,	14	},
				{"NAS-Port-Type"	,	"Ethernet"				,	15	}
			};

struct Acct_Terminate Acct_Terminate_Values[ACCT_TERM_MAX] = 
			{
				{"Acct_terminate-Cause"	,	"User-Request"			,	1	},
				{"Acct_terminate-Cause"	,	"Lost-Carrier"			,	2	},
				{"Acct_terminate-Cause"	,	"Lost-Service"			,	3	},
				{"Acct_terminate-Cause"	,	"Idle-Timeout"			,	4	},
				{"Acct_terminate-Cause"	,	"Session-Timeout"		,	5	},
				{"Acct_terminate-Cause"	,	"Admin-Reset"			,	6	},
				{"Acct_terminate-Cause"	,	"Admin-Reboot"			,	7	},
				{"Acct_terminate-Cause"	,	"Port-Error"			,	8	},
				{"Acct_terminate-Cause"	,	"NAS-Error"				,	9	},
				{"Acct_terminate-Cause"	,	"NAS-Request"			,	10	},
				{"Acct_terminate-Cause"	,	"NAS-Reboot"			,	11	},
				{"Acct_terminate-Cause"	,	"Port-Unneeded"			,	12	},
				{"Acct_terminate-Cause"	,	"Port-Preempted"		,	13	},
				{"Acct_terminate-Cause"	,	"Port-Suspended"		,	14	},
				{"Acct_terminate-Cause"	,	"Service-Unavailable"	,	15	},
				{"Acct_terminate-Cause"	,	"Callback"				,	16	},
				{"Acct_terminate-Cause"	,	"User-Error"			,	17	},
				{"Acct_terminate-Cause"	,	"Host-Request"			,	18	}
			};

struct Non_Protocol_Auth_Type Non_Protocol_Auth_Type_Values[NON_PROTO_AUTH_MAX] = 
			{
				{"Auth-Type"	,	"Local"			,	0	},
				{"Auth-Type"	,	"System"		,	1	},
				{"Auth-Type"	,	"SecurID"		,	2	},
				{"Auth-Type"	,	"Crypt-Local"	,	3	},
				{"Auth-Type"	,	"Reject"		,	4	},
				{"Auth-Type"	,	"Pam"			,	253	},
				{"Auth-Type"	,	"Accept"		,	254	}
			};

struct Server_Config Server_Config_Values[SERVER_CONF_MAX] = 
			{
				{"Server-Config"	,	"Password-Expiration"	,	30	},
				{"Server-Config"	,	"Password-Warning"		,	5	}
			};

void bytes2md5(CC *data, int len, char *md5buf)
{
	// Based on https://www.openssl.org/docs/manmaster/man3/EVP_DigestUpdate.html
	EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
	const EVP_MD *md = EVP_md5();
	unsigned char md_value[EVP_MAX_MD_SIZE];
	UI md_len, i;
	EVP_DigestInit_ex(mdctx, md, NULL);
	EVP_DigestUpdate(mdctx, data, len);
	EVP_DigestFinal_ex(mdctx, md_value, &md_len);
	EVP_MD_CTX_free(mdctx);
	for (i = 0; i < md_len; i++)
	{
		snprintf(&(md5buf[i * 2]), 16 * 2, "%02x", md_value[i]);
	}
}

char* IPAddressToString(int ip , UC *Ip_Address)
{
	sprintf(Ip_Address,"%d.%d.%d.%d", (ip & 0xFF000000) >> 24, (ip & 0x00FF0000) >> 16, (ip & 0x0000FF00) >> 8, (ip & 0x000000FF));
}

void char2hex(UC *source,UC *target,US len)
{
	US i=0;
	for(i=0;i<len;i++)
		sprintf((char*)target+(2*i),(CC *)"%02X",source[i]);
}

void Convert_Timestamp_To_DateTime(time_t rawtime , char *output)
{
	struct tm  ts;
	char buf[80]={0};
	
	// Format time, "mm ddd yyyy hh:mm:ss zzz"
	ts = *localtime(&rawtime);
	strftime(buf, sizeof(buf), "%b %m %d %Y %H:%M:%S %Z", &ts);
	//~ printf("%s\n", buf);  fflush(stdout);
	
	strcpy(output , buf);
}

void send4Debug(UC flg,UC* buf, UI len)
{
	UI tally=0;
	switch(flg)
	{
		case 1:
				for(tally=0;tally<len;tally++)
				{
					printf("%c ",buf[tally]);
					if((tally+1)%16==0) 
						printf("\n");
					fflush(stdout);
				}
				break;
				
		case 0:
				printf("\n"); fflush(stdout);
				for(tally=0;tally<len;tally++)
				{
					printf("%02X ",buf[tally]);
					if((tally+1)%16==0) printf("\n");
				}
				printf("\n"); fflush(stdout);
				
				break;
	}
}

long long int convertHexTodec(UC * str)
{
    long long decimal = 0, base = 1;
    long long int i = 0, value, length;
    
    length = strlen(str);
    for(i = length--; i >= 0; i--)
    {
        if(str[i] >= '0' && str[i] <= '9')
        {
            decimal += (str[i] - 48) * base;
            base *= 16;
        }
        else if(str[i] >= 'A' && str[i] <= 'F')
        {
            decimal += (str[i] - 55) * base;
            base *= 16;
        }
        else if(str[i] >= 'a' && str[i] <= 'f')
        {
            decimal += (str[i] - 87) * base;
            base *= 16;
        }
    }
    //~ printf("\nHexadecimal number = %s", str);    fflush(stdout);
    //~ printf("Decimal number = %lld\n", decimal);  fflush(stdout);
    
    return decimal;
}

void ProcessPacket(UC* buffer, int size)
{
	struct iphdr *iph;
	
	//Get the IP Header part of this packet , excluding the ethernet header
	if(UDP==1)
		iph = (struct iphdr*)buffer;
	else
		iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
	
	++total;
	
	//~ printf("\niph->protocol : %d\n\n",iph->protocol); fflush(stdout);
	
	switch (iph->protocol) //Check the Protocol and do accordingly...
	{
		//~ case 1:  //ICMP Protocol
			//~ ++icmp;
			//~ print_icmp_packet( buffer , size);
			//~ break;
		
		//~ case 2:  //IGMP Protocol
			//~ ++igmp;
			//~ break;
		
		//~ case 6:  //TCP Protocol
			//~ ++tcp;
			//~ print_tcp_packet(buffer , size);
			//~ break;
		
		case 17: //UDP Protocol
			++udp;
			print_udp_packet(buffer , size);
			break;
		
		default: //Some Other Protocol like ARP etc.
			++others;
			break;
	}
	//~ printf("TCP : %d   UDP : %d   ICMP : %d   IGMP : %d   Others : %d   Total : %d\r\n", tcp , udp , icmp , igmp , others , total);  fflush(stdout);
}

void print_ethernet_header(UC *Buffer, int Size)
{
	struct ethhdr *eth = (struct ethhdr *)Buffer;
	
	if(SAVE_DATA == 1)
	{
		fprintf(logfile , "\n");
		fprintf(logfile , "Ethernet Header\n");
		fprintf(logfile , "   |-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5] );
		fprintf(logfile , "   |-Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5] );
		fprintf(logfile , "   |-Protocol            : %u \n",(US)eth->h_proto);
	}
	
	printf("\n");  fflush(stdout);
	printf("Ethernet Header\n");  fflush(stdout);
	printf("   |-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5] );  fflush(stdout);
	printf("   |-Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5] ); fflush(stdout);
	printf("   |-Protocol            : %u \n",(US)eth->h_proto); fflush(stdout);
}

void print_ip_header(UC* Buffer, int Size)
{
	US iphdrlen;
	struct iphdr *iph;
	
	if(UDP==1)
		iph = (struct iphdr*)Buffer;
	else
		iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr) );
	
	print_ethernet_header(Buffer , Size);
	
	iphdrlen =iph->ihl*4;
	
	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;
	
	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;
	
	printf("\n");                                                                                   fflush(stdout);
	printf("IP Header\n");                                                                          fflush(stdout);
	printf("   |-IP Version        : %d\n",(UI)iph->version);                                       fflush(stdout);
	printf("   |-IP Header Length  : %d DWORDS or %d Bytes\n",(UI)iph->ihl,((UI)(iph->ihl))*4);     fflush(stdout);
	printf("   |-Type Of Service   : %d\n",(UI)iph->tos);                                           fflush(stdout);
	printf("   |-IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(iph->tot_len));             fflush(stdout);
	printf("   |-Identification    : %d\n",ntohs(iph->id));                                         fflush(stdout);
	printf("   |-TTL      : %d\n",(UI)iph->ttl);                                                    fflush(stdout);
	printf("   |-Protocol : %d\n",(UI)iph->protocol);                                               fflush(stdout);
	printf("   |-Checksum : %d\n",ntohs(iph->check));                                               fflush(stdout);
	printf("   |-Source IP        : %s\n" , inet_ntoa(source.sin_addr) );                           fflush(stdout);
	printf("   |-Destination IP   : %s\n" , inet_ntoa(dest.sin_addr) );                             fflush(stdout);
	
	if(SAVE_DATA == 1)
	{
		fprintf(logfile , "\n");
		fprintf(logfile , "IP Header\n");
		fprintf(logfile , "   |-IP Version        : %d\n",(UI)iph->version);
		fprintf(logfile , "   |-IP Header Length  : %d DWORDS or %d Bytes\n",(UI)iph->ihl,((UI)(iph->ihl))*4);
		fprintf(logfile , "   |-Type Of Service   : %d\n",(UI)iph->tos);
		fprintf(logfile , "   |-IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(iph->tot_len));
		fprintf(logfile , "   |-Identification    : %d\n",ntohs(iph->id));
		fprintf(logfile , "   |-TTL      : %d\n",(UI)iph->ttl);
		fprintf(logfile , "   |-Protocol : %d\n",(UI)iph->protocol);
		fprintf(logfile , "   |-Checksum : %d\n",ntohs(iph->check));
		fprintf(logfile , "   |-Source IP        : %s\n" , inet_ntoa(source.sin_addr) );
		fprintf(logfile , "   |-Destination IP   : %s\n" , inet_ntoa(dest.sin_addr) );
	}
}

void print_tcp_packet(UC* Buffer, int Size)
{
	US iphdrlen;
	struct iphdr *iph;
	struct tcphdr *tcph;
	int header_size;
	
	if(UDP==1)
		iph = (struct iphdr*)Buffer;
	else
		iph = (struct iphdr *)( Buffer  + sizeof(struct ethhdr) );
	
	iphdrlen = iph->ihl*4;
	
	if(UDP==1)
		tcph=(struct tcphdr*)(Buffer + iphdrlen);
	else
		tcph=(struct tcphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));
	
	header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;
	
	if(SAVE_DATA == 1)
		fprintf(logfile , "\n\n***********************TCP Packet*************************\n");	
	
	printf("\n\n***********************TCP Packet*************************\n");	 fflush(stdout);
    
	print_ip_header(Buffer,Size);
	
	if(SAVE_DATA == 1)
	{
		fprintf(logfile , "\n");
		fprintf(logfile , "TCP Header\n");
		fprintf(logfile , "   |-Source Port      : %u\n",ntohs(tcph->source));
		fprintf(logfile , "   |-Destination Port : %u\n",ntohs(tcph->dest));
		fprintf(logfile , "   |-Sequence Number    : %u\n",ntohl(tcph->seq));
		fprintf(logfile , "   |-Acknowledge Number : %u\n",ntohl(tcph->ack_seq));
		fprintf(logfile , "   |-Header Length      : %d DWORDS or %d BYTES\n" ,(UI)tcph->doff,(UI)tcph->doff*4);
		fprintf(logfile , "   |-Urgent Flag          : %d\n",(UI)tcph->urg);
		fprintf(logfile , "   |-Acknowledgement Flag : %d\n",(UI)tcph->ack);
		fprintf(logfile , "   |-Push Flag            : %d\n",(UI)tcph->psh);
		fprintf(logfile , "   |-Reset Flag           : %d\n",(UI)tcph->rst);
		fprintf(logfile , "   |-Synchronise Flag     : %d\n",(UI)tcph->syn);
		fprintf(logfile , "   |-Finish Flag          : %d\n",(UI)tcph->fin);
		fprintf(logfile , "   |-Window         : %d\n",ntohs(tcph->window));
		fprintf(logfile , "   |-Checksum       : %d\n",ntohs(tcph->check));
		fprintf(logfile , "   |-Urgent Pointer : %d\n",tcph->urg_ptr);
		fprintf(logfile , "\n");
		fprintf(logfile , "                        DATA Dump                         ");
		fprintf(logfile , "\n");
        
		fprintf(logfile , "IP Header\n");
	}
	
	printf("\n");                                                                                   fflush(stdout);
	printf("TCP Header\n");                                                                         fflush(stdout);
	printf("   |-Source Port      : %u\n",ntohs(tcph->source));                                     fflush(stdout);
	printf("   |-Destination Port : %u\n",ntohs(tcph->dest));                                       fflush(stdout);
	printf("   |-Sequence Number    : %u\n",ntohl(tcph->seq));                                      fflush(stdout);
	printf("   |-Acknowledge Number : %u\n",ntohl(tcph->ack_seq));                                  fflush(stdout);
	printf("   |-Header Length      : %d DWORDS or %d BYTES\n" ,(UI)tcph->doff,(UI)tcph->doff*4);   fflush(stdout);
	printf("   |-Urgent Flag          : %d\n",(UI)tcph->urg);                                       fflush(stdout);
	printf("   |-Acknowledgement Flag : %d\n",(UI)tcph->ack);                                       fflush(stdout);
	printf("   |-Push Flag            : %d\n",(UI)tcph->psh);                                       fflush(stdout);
	printf("   |-Reset Flag           : %d\n",(UI)tcph->rst);                                       fflush(stdout);
	printf("   |-Synchronise Flag     : %d\n",(UI)tcph->syn);                                       fflush(stdout);
	printf("   |-Finish Flag          : %d\n",(UI)tcph->fin);                                       fflush(stdout);
	printf("   |-Window         : %d\n",ntohs(tcph->window));                                       fflush(stdout);
	printf("   |-Checksum       : %d\n",ntohs(tcph->check));                                        fflush(stdout);
	printf("   |-Urgent Pointer : %d\n",tcph->urg_ptr);                                             fflush(stdout);
	printf("\n");                                                                                   fflush(stdout);
	printf("                        DATA Dump                         ");                           fflush(stdout);
	printf("\n");                                                                                   fflush(stdout);
    
	printf("IP Header\n"); fflush(stdout);
	
	PrintData(Buffer,iphdrlen);
	
	if(SAVE_DATA == 1)
		fprintf(logfile , "TCP Header\n");
	
	printf("TCP Header\n");  fflush(stdout);
	PrintData(Buffer+iphdrlen,tcph->doff*4);
	
	if(SAVE_DATA == 1)
		printf("Data Payload\n");    fflush(stdout);
	
	if(SAVE_DATA == 1)
		fprintf(logfile , "Data Payload\n");
	
	printf("Data Payload\n");    fflush(stdout);
	
	if(UDP==1)
		PrintData(Buffer + iphdrlen + tcph->doff*4 , (Size - tcph->doff*4-iph->ihl*4) );
	else
		PrintData(Buffer + header_size , Size - header_size );
	
	if(SAVE_DATA == 1)
		fprintf(logfile , "\n###########################################################");
	
	printf("\n###########################################################");     fflush(stdout);
}

// function to convert decimal to binary
void decToBinary(int n , char *buf)
{
    // array to store binary number
    int binaryNum[32];
    int i=0,j=0,k=0;
    
    memset(buf,0x00,sizeof(buf));
    
    while (n > 0)
    {
        // storing remainder in binary array
        binaryNum[i] = n % 2;
        n = n / 2;
        i++;
    }
    
    // printing binary array in reverse order
    for (j = i - 1; j >= 0; j--)
    {
        buf[k++] =  binaryNum[j] + 0x30;
    }
}

int binaryToDecimal(int n)
{
    int num = n;
    int dec_value = 0;
    int last_digit=0;
    int temp=0;
    
    // Initializing base value to 1, i.e 2^0
    int base = 1;
    
    temp = num;
    
    while (temp)
    {
        last_digit = temp % 10;
        temp = temp / 10;
        
        dec_value += last_digit * base;
        base = base * 2;
    }
 
    return dec_value;
}

void fetch_imsi(UC * temp , UC * data , int len)
{
    int i=0;
    int j=0;
    int val=0;
    
    UC buff[50]={0};
    UC tempIMSI[50]={0};

    //~ printf("\ntemp : %02x",temp[0]); fflush(stdout);
    
    memset(data,0x00,sizeof(data));
    
    for(i=0 ; i<len ; i++)
    {
        val = REV(temp[i]);
        
        //~ printf("\nval : %02x\n",val); fflush(stdout);
        
        buff[j] = val;
        
        //~ printf("\nimsi[%d] : %x\n",j,buff[j]); fflush(stdout);
        
        j++;
    }
    
    char2hex(buff , tempIMSI , j);
    
    len = (len>1)?((len*2)-1):2;
    
    //~ printf("\nlen : %d\n",len); fflush(stdout);
    
    for(i=0 ; i<len ; i++)
    {
        data[i] = tempIMSI[i];
        
        //~ printf("\ntempIMSI[%d] : %c",i,tempIMSI[i]); fflush(stdout);
    }
    
    //~ printf("\ndata : %s\n",data); fflush(stdout);
}

void Fetch_GTP_Data(UC *str , int Val_len)
{
	int len             =   0;
    int GTP_flag        =   0;
    int msg_type        =   0;
    int msgLen          =   0;
    int spare           =   0;
    int IE_type         =   0;
    int IE_Len          =   0;
    int CR_flag         =   0;
    int seq_no          =   0;      // Sequence Number
    int TEID            =   0;      // Tunnel Endpoint Identifier (TEID)
    int MSISDN_type     =   0;      // Mobile Station International Subscriber Directory Number (MSISDN)  Type
    int MSISDN_len      =   0;      // MSISDN Length
    int Version         =   0;      // GTP Version
    int MEI_type        =   0;      // Mobile Equipment Identity (MEI) Type
    int MEI_len         =   0;      // MEI Length
    int ULI_type        =   0;      // User Location Info (ULI) : CGI SAI RAI TAI ECGI LAI 
    int ULI_len         =   0;      // ULI Length
    int ULI_flag        =   0;      // ULI Flag
    
    int CGI_MCC         =   0;      // Mobile Country Code (MCC)
    int CGI_MNC         =   0;      // Mobile Network Code (MNC)
    int CGI_LAC         =   0;      // Location Area Code (LAC)
    int CGI_CI          =   0;      // Cell Identity (CI)
    
    int SAI_MCC         =   0;      // Mobile Country Code (MCC)
    int SAI_MNC         =   0;      // Mobile Network Code (MNC)
    int SAI_LAC         =   0;      // Location Area Code (LAC)
    int SAI_SAC         =   0;      // Service Area Code (CI)
    
    int LAI_MCC         =   0;      // Mobile Country Code (MCC)
    int LAI_MNC         =   0;      // Mobile Network Code (MNC)
    int LAI_LAC         =   0;      // Location Area Code (LAC)
    int LAI_CI          =   0;      // Cell Identity (CI)
    
    int RAI_MCC         =   0;      // Mobile Country Code (MCC)
    int RAI_MNC         =   0;      // Mobile Network Code (MNC)
    int RAI_LAC         =   0;      // Location Area Code (LAC)
    int RAI_RAC         =   0;      // Routing Area Code (RAC)
        
    int TAI_MCC         =   0;      // Mobile Country Code (MCC)
    int TAI_MNC         =   0;      // Mobile Network Code (MNC)
    int TAI_TAC         =   0;      // Tracking Area Code (TAC)
    
    int ECGI_MCC        =   0;      // Mobile Country Code (MCC)
    int ECGI_MNC        =   0;      // Mobile Network Code (MNC)
    int ECGI_SPARE      =   0;      // spare
    int ECGI_ECI        =   0;      // ECI (E-UTRAN Cell Identifier)
    
    UC LAI              =   0;      // LAI (Location Area Identifier)
    UC ECGI             =   0;      // E-UTRAN Cell Global Identifier (ECGI)
    UC TAI              =   0;      // Tracking Area Identity (TAI)
    UC RAI              =   0;      // Routeing Area Identity (RAI)
    UC SAI              =   0;      // Service Area Identity (SAI)
    UC CGI              =   0;      // Cell Global Identity (CGI)
    
    UC buffer           [4096]  =   {0};
    UC temp             [50]    =   {0};
    UC GTP_flag_bin     [50]    =   {0};
    UC IMSI             [20]    =   {0};    // International Mobile Subscriber Identity (IMSI) Value
    UC MSISDN           [20]    =   {0};    // Mobile Station International Subscriber Directory Number (MSISDN) 
    UC MEI              [20]    =   {0};    // Mobile Equipment Identity (MEI) Value
    UC ULI_flag_bin     [20]    =   {0};    // User Location Info (ULI) flag binary value e.g. 11111111
    
    memcpy(buffer , str , Val_len);
    
    //~ send4Debug(0 , buffer , Val_len);
    
    GTP_flag    = (UI)buffer[len];                         len++;
    printf("\nGTP_flag : 0x%02x",GTP_flag); fflush(stdout);
    
    decToBinary(GTP_flag , GTP_flag_bin);
    //~ printf("\nGTP_flag_bin : %s\n",GTP_flag_bin); fflush(stdout);
    
    memset(temp,0x00,sizeof(temp));
    memcpy(temp , GTP_flag_bin , 2);
    Version = binaryToDecimal(atoi((const char*)temp));
    printf("\nVersion : %d",Version); fflush(stdout);
    
    if(Version==2)
    {
        msg_type = (UI)buffer[len];                        len++;
        printf("\nmsg_type : 0x%02x",msg_type); fflush(stdout);
        
        memset(temp,0x00,sizeof(temp));
        char2hex(buffer+len,temp,2);                       len+=2;
        msgLen = (int)strtol(temp, NULL, 16);
        printf("\nmsgLen : %d",msgLen); fflush(stdout);
        
        if (GTP_flag_bin[3]=='1')
        {
            //~ printf("\n\nTEID Bit is set to 1"); fflush(stdout);
            
            memset(temp,0x00,sizeof(temp));
            char2hex(buffer+len,temp,4);                   len+=4;
            TEID = (int)strtol(temp, NULL, 16);
            
            printf("\nTEID : 0x%08x",TEID); fflush(stdout);
        }
        else
        {
            printf("\nTEID Bit is set to 0\n"); fflush(stdout);
        }
        
        memset(temp,0x00,sizeof(temp));
        char2hex(buffer+len,temp,3);                       len+=3;
        seq_no  = (int)strtol(temp, NULL, 16);      
        printf("\nseq_no : %d",seq_no); fflush(stdout);
        
        spare   = (UI)buffer[len];                         len++;
        printf("\nspare : %d",spare); fflush(stdout);
        
        IE_type = (UI)buffer[len];                         len++;
        printf("\nIE_type : %d",IE_type); fflush(stdout);
        
        memset(temp,0x00,sizeof(temp));
        char2hex(buffer+len,temp,2);                       len+=2;
        IE_Len  = (int)strtol(temp, NULL, 16);      
        printf("\nIE_Len : %d",IE_Len); fflush(stdout);
        
        CR_flag = (UI)buffer[len];                         len++;
        
        fetch_imsi(buffer+len , IMSI , IE_Len);            len+=8;
        printf("\nIMSI : %s",IMSI); fflush(stdout);
        
        MSISDN_type = (UI)buffer[len];                     len++;
        printf("\nMSISDN_type : %d",MSISDN_type); fflush(stdout);
        
        memset(temp,0x00,sizeof(temp));       
        char2hex(buffer+len,temp,2);                       len+=2;
        MSISDN_len  = (int)strtol(temp, NULL, 16);      
        printf("\nMSISDN_len : %d",MSISDN_len); fflush(stdout);
        
        CR_flag = (UI)buffer[len];                         len++;
        
        fetch_imsi(buffer+len , MSISDN , MSISDN_len);      len+=7;
        printf("\nMSISDN : %s",MSISDN); fflush(stdout);
        
        MEI_type = (UI)buffer[len];                        len++;
        printf("\nMEI_type : %d",MEI_type); fflush(stdout);
        
        memset(temp,0x00,sizeof(temp));       
        char2hex(buffer+len,temp,2);                       len+=2;
        MEI_len  = (int)strtol(temp, NULL, 16);      
        printf("\nMEI_len : %d",MEI_len); fflush(stdout);
        
        CR_flag = (UI)buffer[len];                         len++;
        
        fetch_imsi(buffer+len , MEI , MEI_len);            len+=8;
        printf("\nMEI : %s",MEI); fflush(stdout);
        
        ULI_type = (UI)buffer[len];                        len++;
        printf("\nULI_type : %d",ULI_type); fflush(stdout);
        
        memset(temp,0x00,sizeof(temp));       
        char2hex(buffer+len,temp,2);                       len+=2;
        ULI_len  = (int)strtol(temp, NULL, 16);      
        printf("\nULI_len : %d",ULI_len); fflush(stdout);
        
        CR_flag = (UI)buffer[len];                         len++;
        
        ULI_flag = (UI)buffer[len];                        len++;
        printf("\nULI_flag : %02x",ULI_flag); fflush(stdout);
        
        decToBinary(ULI_flag , ULI_flag_bin);
        //~ printf("\nULI_flag_bin : %s",ULI_flag_bin); fflush(stdout);
        
        LAI     =   ULI_flag_bin[2];
        ECGI    =   ULI_flag_bin[3];
        TAI     =   ULI_flag_bin[4];
        RAI     =   ULI_flag_bin[5];
        SAI     =   ULI_flag_bin[6];
        CGI     =   ULI_flag_bin[7];
        
        printf("\n");
        
        printf("\nLAI : %c",LAI); fflush(stdout);
        printf("\nECGI : %c",ECGI); fflush(stdout);
        printf("\nTAI : %c",TAI); fflush(stdout);
        printf("\nRAI : %c",TAI); fflush(stdout);
        printf("\nSAI : %c",SAI); fflush(stdout);
        printf("\nCGI : %c",CGI); fflush(stdout);
        
        printf("\n");
        
        if(CGI == '1')
        {
            fetch_imsi(buffer+len , temp , 2);            len+=2;
            CGI_MCC  = atoi((const char*)temp);
            printf("\nCGI_MCC : %d",CGI_MCC); fflush(stdout);
            
            fetch_imsi(buffer+len , temp , 1);            len+=1;
            CGI_MNC  = atoi((const char*)temp);
            printf("\nCGI_MNC : %d",CGI_MNC); fflush(stdout);
            
            memset(temp,0x00,sizeof(temp));
            char2hex(buffer+len,temp,2);                   len+=2;
            CGI_LAC = (int)strtol(temp, NULL, 16);
            printf("\nCGI_LAC : 0x%04x",CGI_LAC); fflush(stdout);
            
            memset(temp,0x00,sizeof(temp));
            char2hex(buffer+len,temp,2);                   len+=2;
            CGI_CI = (int)strtol(temp, NULL, 16);
            printf("\nCGI_CI : 0x%04x",CGI_CI); fflush(stdout);
            
            printf("\n");
        }
        
        if(SAI == '1')
        {
            fetch_imsi(buffer+len , temp , 2);            len+=2;
            SAI_MCC  = atoi((const char*)temp);
            printf("\nSAI_MCC : %d",SAI_MCC); fflush(stdout);
            
            fetch_imsi(buffer+len , temp , 1);            len+=1;
            SAI_MNC  = atoi((const char*)temp);
            printf("\nSAI_MNC : %d",SAI_MNC); fflush(stdout);
            
            memset(temp,0x00,sizeof(temp));
            char2hex(buffer+len,temp,2);                   len+=2;
            SAI_LAC = (int)strtol(temp, NULL, 16);
            printf("\nSAI_LAC : 0x%04x",SAI_LAC); fflush(stdout);
            
            memset(temp,0x00,sizeof(temp));
            char2hex(buffer+len,temp,2);                   len+=2;
            SAI_SAC = (int)strtol(temp, NULL, 16);
            printf("\nSAI_SAC : 0x%04x",SAI_SAC); fflush(stdout);
            
            printf("\n");
        }
        
        if(RAI == '1')
        {
            fetch_imsi(buffer+len , temp , 2);            len+=2;
            RAI_MCC  = atoi((const char*)temp);
            printf("\nRAI_MCC : %d",RAI_MCC); fflush(stdout);
            
            fetch_imsi(buffer+len , temp , 1);            len+=1;
            RAI_MNC  = atoi((const char*)temp);
            printf("\nRAI_MNC : %d",RAI_MNC); fflush(stdout);
            
            memset(temp,0x00,sizeof(temp));
            char2hex(buffer+len,temp,2);                   len+=2;
            RAI_LAC = (int)strtol(temp, NULL, 16);
            printf("\nRAI_LAC : 0x%04x",RAI_LAC); fflush(stdout);
            
            memset(temp,0x00,sizeof(temp));
            char2hex(buffer+len,temp,2);                   len+=2;
            RAI_RAC = (int)strtol(temp, NULL, 16);
            printf("\nRAI_RAC : 0x%04x",RAI_RAC); fflush(stdout);
            
            printf("\n");
        }
        
        if(TAI == '1')
        {
            fetch_imsi(buffer+len , temp , 2);            len+=2;
            TAI_MCC  = atoi((const char*)temp);
            printf("\nTAI_MCC : %d",TAI_MCC); fflush(stdout);
            
            fetch_imsi(buffer+len , temp , 1);            len+=1;
            TAI_MNC  = atoi((const char*)temp);
            printf("\nTAI_MNC : %d",TAI_MNC); fflush(stdout);
            
            memset(temp,0x00,sizeof(temp));
            char2hex(buffer+len,temp,2);                   len+=2;
            //~ printf("\ntemp : %s\n",temp); fflush(stdout);
            
            TAI_TAC = (int)strtol(temp, NULL, 16);
            printf("\nTAI_TAC : 0x%04x",TAI_TAC); fflush(stdout);
            
            printf("\n");
        }
        
        if(ECGI == '1')
        {
            fetch_imsi(buffer+len , temp , 2);            len+=2;
            ECGI_MCC  = atoi((const char*)temp);
            printf("\nECGI_MCC : %d",ECGI_MCC); fflush(stdout);
            
            fetch_imsi(buffer+len , temp , 1);            len+=1;
            ECGI_MNC  = atoi((const char*)temp);
            printf("\nECGI_MNC : %d",ECGI_MNC); fflush(stdout);
            
            memset(temp,0x00,sizeof(temp));
            char2hex(buffer+len,temp,4);                   len+=4;
            ECGI_ECI= convertHexTodec(temp);
            
            //~ printf("\ntemp : %s\n",temp); fflush(stdout);
            
            sscanf(temp,"%2d",&ECGI_SPARE);
            printf("\nECGI_SPARE : %d",ECGI_SPARE); fflush(stdout);
            
            printf("\nECGI_ECI : %d",ECGI_ECI); fflush(stdout);
            
            printf("\n");   
        }
        
        if(LAI == '1')
        {
            fetch_imsi(buffer+len , temp , 2);            len+=2;
            LAI_MCC  = atoi((const char*)temp);
            printf("\nLAI_MCC : %d",LAI_MCC); fflush(stdout);
            
            fetch_imsi(buffer+len , temp , 1);            len+=1;
            LAI_MNC  = atoi((const char*)temp);
            printf("\nLAI_MNC : %d",LAI_MNC); fflush(stdout);
            
            memset(temp,0x00,sizeof(temp));
            char2hex(buffer+len,temp,2);                   len+=2;
            LAI_LAC = (int)strtol(temp, NULL, 16);
            printf("\nLAI_LAC : 0x%04x",LAI_LAC); fflush(stdout);
        }
    }
    
    printf("\n\n");
}

int getWords(char *base, char target[10][20])
{
	int n=0,i,j=0;
	
	for(i=0;1;i++)
	{
		if(base[i]!=' '){
			target[n][j++]=base[i];
		}
		else{
			target[n][j++]='\0';//insert NULL
			n++;
			j=0;
		}
		if(base[i]=='\0')
		    break;
	}
	return n;
	
}

int read_MCC_file(UC *MCC , UC *MNC , UC *Country , UC *Network)
{
	FILE *fp=0;
	
	char * line = NULL;
	size_t len  = 0;
	ssize_t line_size;
	
    char string[1024] = {0};
    
    char arr[10][20];
    
	int i=0;
    int n=0;
    
	fp = fopen((const char *)"MCC_Values",(const char *)"r");
	if(fp == NULL)
	{
		fclose(fp);
		return -1;
	}
	
	while ((line_size = getline(&line, &len, fp)) != -1)
	{
		//~ printf("\nline : %s\n",line); fflush(stdout);
        
        n=getWords(line,arr);
	
        //~ for(i=0;i<=n;i++)
            //~ printf("%s\n",arr[i]);
            
        if( (strcmp(arr[0] , MCC)==0) && (strcmp(arr[1] , MNC)==0) )
        {
            strcpy(Country , arr[3]);
            memcpy(Network , arr[5] , (strlen(arr[5])-1));
            
            //~ printf("\nCountry Code (MCC): %s",Country); fflush(stdout);
            //~ printf("\nNetwork Code (MNC): %s [%d]",Network,strlen(Network)); fflush(stdout);
            //~ printf("\n\n");
            
            break;
        }
	}
	
	fclose(fp);
	
	return 0;
}

void Fetch_Radius_Attributes(UC *str , int len)
{
	int i           =   0;
    int j           =   0;
    int k           =   0;
	int num         =   0;
	int data_len    =   0;
	int Val_len     =   0;
    
    long long int value=0;
    
	UC buff         [1024]  =   {0};
	UC temp         [50]    =   {0};
    UC Ip_Address   [20]    =   {0};
    
	//~ send4Debug(0,str,len);
	
    ht = create_table(CAPACITY);
    
	for(i=0 ; i<len ; )
	{
		for(j=0 ; j < (RAD_ATTR_MAX) && (strlen(radius_attr[j].type)>0) ; j++)
		{
			//~ printf("\nradius_attr[%d].value : %d type : %s\n",j,radius_attr[j].value,radius_attr[j].type); fflush(stdout);
			
			if((UI)(str[i]) == radius_attr[j].value && (strcmp(radius_attr[j].type,"string")==0))
			{
				Val_len = ((UI)(str[i+1]));
				
				data_len = Val_len - 2;
				
                //~ printf("\nVal_len : %d\n",Val_len); fflush(stdout);
                
				if((UI)(str[i])==26)
				{
                    memset(buff,0x00,sizeof(buff));
                    
                    memcpy(buff , str+i+1+1 , data_len);
                    
                    char2hex(buff,temp,4);
                    value = convertHexTodec(temp);
                    //~ printf("\nVendor ID : %lld",value); fflush(stdout);
                    
                    if(value==10415)
                    {
                        int GPP_type=0;
                        int GPP_data_len=0;
                        
                        UC Country  [30]    =   {0};
                        UC Network  [30]    =   {0};
                        UC MCC      [10]    =   {0};
                        UC MNC      [10]    =   {0};
                        UC LAC      [10]    =   {0};
                        UC SAC      [10]    =   {0};
                        
                        GPP_type        = (UI)buff[4];
                        GPP_data_len    = (UI)buff[5];
                        
                        printf("\nVendor : 3GPP-User-Location-Info\n"); fflush(stdout);
                        
                        //~ printf("\nGPP_type : %d",GPP_type); fflush(stdout);
                        //~ printf("\nGPP_data_len : %d",GPP_data_len); fflush(stdout);
                        
                        memset(temp,0x00,sizeof(temp));
                        fetch_imsi(buff+7 , MCC , 2);
                        
                        memset(temp,0x00,sizeof(temp));
                        fetch_imsi(buff+9 , MNC , 1);
                        
                        char2hex(buff+10,temp,2);
                        value = convertHexTodec(temp);
                        sprintf((char*)LAC,(const char*)"%lld",value);
                        
                        char2hex(buff+12,temp,2);
                        value = convertHexTodec(temp);
                        sprintf((char*)SAC,(const char*)"%lld",value);
                        
                        if(read_MCC_file(MCC , MNC , Country , Network) == 0)
                        {
                            printf("    Mobile Country Code (MCC): %s (%s)\n",Country , MCC); fflush(stdout);
                            printf("    Mobile Network Code (MNC): %s (%s)\n",Network , MNC); fflush(stdout);
                            printf("    Location Area Code (LAC): %s\n",LAC); fflush(stdout);
                            printf("    Service Area Code (SAC): %s\n",SAC); fflush(stdout);
                        }
                        
                        ht_insert(ht, "Mobile Country Code", Country);
                        ht_insert(ht, "Mobile Network Code", Network);
                        ht_insert(ht, "Location Area Code", LAC);
                        ht_insert(ht, "Service Area Code", SAC);
                    }
				}
                else
                {
                    memcpy(buff , str+i+1+1 , data_len);
				
                    buff[data_len]='\0';
                    
                    printf("%s = %s\n",radius_attr[j].attribute,buff); fflush(stdout);
					
					ht_insert(ht, radius_attr[j].attribute, buff);
                }
				break;
			}
			else if((UI)(str[i]) == radius_attr[j].value && (strcmp(radius_attr[j].type,"integer")==0))
			{
                //~ printf("\nradius_attr[j].value : %d %d\n",radius_attr[j].value,(UI)(str[i])); fflush(stdout);
                
				Val_len = ((UI)(str[i+1]));
				
				data_len=Val_len - 2;
				
				memcpy(buff , str+i+1+1 , data_len);
                buff[data_len]='\0';
				
				char2hex(buff,temp,data_len);
				
				value = convertHexTodec(temp);
				//~ printf("\nvalue : %lld\n",value); fflush(stdout);
				if((UI)(str[i])!=26)
				{
					//~ printf("\nValue : %lld\n",value); fflush(stdout);
					if(strcmp(radius_attr[j].attribute ,"Event-Timestamp")==0)
					{
						//~ char output[80]={0};
						
						//~ Convert_Timestamp_To_DateTime((time_t)value , output);
						
						//~ printf("%s = %s\n" , radius_attr[j].attribute , output); fflush(stdout);
						
						//~ ht_insert(ht, radius_attr[j].attribute, output);
						
						UC output[50]={0};
						
						sprintf((char*)output , (CC*)"%lld" , value);
						//~ printf("\noutput : %s\n",output); fflush(stdout);
						printf("%s = %s\n" , radius_attr[j].attribute , output); fflush(stdout);
						
						ht_insert(ht, radius_attr[j].attribute, output);
					}
					else if(strcmp(radius_attr[j].attribute ,"Service-Type")==0)
					{
						for(k=0;k<USERTYPE_MAX;k++)
						{
							if(value == User_Types_Values[k].value)
							{
								printf("%s = %s\n" , radius_attr[j].attribute , User_Types_Values[k].Type_name); fflush(stdout);
								
								ht_insert(ht, radius_attr[j].attribute, User_Types_Values[k].Type_name);
							}
						}
					}
					else if(strcmp(radius_attr[j].attribute ,"Framed-Protocol")==0)
					{
						for(k=0;k<FRAME_MAX;k++)
						{
							if(value == Framed_Protocol_Values[k].value)
							{
								printf("%s = %s\n" , radius_attr[j].attribute , Framed_Protocol_Values[k].Type_name); fflush(stdout);
								
								ht_insert(ht, radius_attr[j].attribute, Framed_Protocol_Values[k].Type_name);
							}
						}
					}
					else if(strcmp(radius_attr[j].attribute ,"Framed-Routing")==0)
					{
						for(k=0;k<FRAME_ROUTE_MAX;k++)
						{
							if(value == Framed_Routing_Values[k].value)
							{
								printf("%s = %s\n" , radius_attr[j].attribute , Framed_Routing_Values[k].Type_name); fflush(stdout);
								
								ht_insert(ht, radius_attr[j].attribute, Framed_Routing_Values[k].Type_name);
							}
						}
					}
					else if(strcmp(radius_attr[j].attribute ,"Framed-Compression")==0)
					{
						for(k=0;k<FRAME_COMP_MAX;k++)
						{
							if(value == Framed_Compression_Values[k].value)
							{
								printf("%s = %s\n" , radius_attr[j].attribute , Framed_Compression_Values[k].Type_name); fflush(stdout);
								
								ht_insert(ht, radius_attr[j].attribute, Framed_Compression_Values[k].Type_name);
							}
						}
					}
					else if(strcmp(radius_attr[j].attribute ,"Login-Service")==0)
					{
						for(k=0;k<LOGIN_SERV_MAX;k++)
						{
							if(value == Login_Services_Values[k].value)
							{
								printf("%s = %s\n" , radius_attr[j].attribute , Login_Services_Values[k].Type_name); fflush(stdout);
								
								ht_insert(ht, radius_attr[j].attribute, Login_Services_Values[k].Type_name);
							}
						}
					}
					else if(strcmp(radius_attr[j].attribute ,"Acct-Status-Type")==0)
					{
						for(k=0;k<ACCT_STATUS_MAX;k++)
						{
							if(value == Acct_Status_Values[k].value)
							{
								printf("%s = %s\n" , radius_attr[j].attribute , Acct_Status_Values[k].Type_name); fflush(stdout);
								
								ht_insert(ht, radius_attr[j].attribute, Acct_Status_Values[k].Type_name);
							}
						}
					}
					else if(strcmp(radius_attr[j].attribute ,"Acct-Authentic")==0)
					{
						for(k=0;k<ACCT_AUTH_MAX;k++)
						{
							if(value == Acct_Authentic_Values[k].value)
							{
								printf("%s = %s\n" , radius_attr[j].attribute , Acct_Authentic_Values[k].Type_name); fflush(stdout);
								
								ht_insert(ht, radius_attr[j].attribute, Acct_Authentic_Values[k].Type_name);
							}
						}
					}
					else if(strcmp(radius_attr[j].attribute ,"Termination-Action")==0)
					{
						for(k=0;k<TERMINATION_MAX;k++)
						{
							if(value == Termination_Values[k].value)
							{
								printf("%s = %s\n" , radius_attr[j].attribute , Termination_Values[k].Type_name); fflush(stdout);
								
								ht_insert(ht, radius_attr[j].attribute, Termination_Values[k].Type_name);
							}
						}
					}
					else if(strcmp(radius_attr[j].attribute ,"NAS-Port-Type")==0)
					{	
						for(k=0;k<NAS_MAX;k++)
						{
							if(value == NAS_Port_Values[k].value)
							{
								printf("%s = %s\n" , radius_attr[j].attribute , NAS_Port_Values[k].Type_name); fflush(stdout);
								
								ht_insert(ht, radius_attr[j].attribute, NAS_Port_Values[k].Type_name);
							}
						}
					}
					else if(strcmp(radius_attr[j].attribute ,"Acct-Terminate-Cause")==0)
					{
						for(k=0;k<ACCT_TERM_MAX;k++)
						{
							if(value == Acct_Terminate_Values[k].value)
							{
								printf("%s = %s\n" , radius_attr[j].attribute , Acct_Terminate_Values[k].Type_name); fflush(stdout);
								
								ht_insert(ht, radius_attr[j].attribute, Acct_Terminate_Values[k].Type_name);
							}
						}
					}
					else if(strcmp(radius_attr[j].attribute ,"Auth-Type")==0)
					{
						for(k=0;k<NON_PROTO_AUTH_MAX;k++)
						{
							if(value == Non_Protocol_Auth_Type_Values[k].value)
							{
								printf("%s = %s\n" , radius_attr[j].attribute , Non_Protocol_Auth_Type_Values[k].Type_name); fflush(stdout);
								
								ht_insert(ht, radius_attr[j].attribute, Non_Protocol_Auth_Type_Values[k].Type_name);
							}
						}
					}
					else if(strcmp(radius_attr[j].attribute ,"Server-Config")==0)
					{
						for(k=0;k<SERVER_CONF_MAX;k++)
						{
							if(value == Server_Config_Values[k].value)
							{
								printf("%s = %s\n" , radius_attr[j].attribute , Server_Config_Values[k].Type_name); fflush(stdout);
								
								ht_insert(ht, radius_attr[j].attribute, Server_Config_Values[k].Type_name);
							}
						}
					}
					else
					{
						UC output[50]={0};
						
						sprintf((char*)output , (CC*)"%lld" , value);
						//~ printf("\noutput : %s\n",output); fflush(stdout);
						printf("%s = %s\n" , radius_attr[j].attribute , output); fflush(stdout);
						
						ht_insert(ht, radius_attr[j].attribute, output);
					}
				}
				break;
			}
			else if((UI)(str[i]) == radius_attr[j].value && (strcmp(radius_attr[j].type,"ipaddr")==0))
			{
				Val_len = ((UI)(str[i+1]));
				data_len=Val_len - 2;
				
				memcpy(buff , str+i+1+1 , data_len);
				buff[data_len]='\0';
				
				char2hex(buff,temp,data_len);
				
				num = (int)strtol(temp, NULL, 16);
				//~ printf("\nNum : %x\n",num); fflush(stdout);
				
				IPAddressToString(num , Ip_Address);
				
				if((UI)(str[i])!=26)
				{
					printf("%s = %s\n" , radius_attr[j].attribute , Ip_Address); fflush(stdout);
					
					ht_insert(ht, radius_attr[j].attribute, Ip_Address);
				}
				
				break;
			}
			else if((UI)(str[i]) == radius_attr[j].value && (strcmp(radius_attr[j].type,"ipv6prefix")==0))
			{
				UC prefix[4]={0};
				UC prefix_temp[4]={0};
				UC ipv6_temp1[50]={0};
				UC ipv6_temp2[50]={0};
				UC output[100]={0};
				
				int len=0;
				
				Val_len = ((UI)(str[i+1]));
				
				data_len=Val_len - 2 - 2;
				
				memcpy(prefix , str+i+1+1 , 2);
				prefix[2]='\0';
				
				char2hex(prefix,prefix_temp,2);
				value = convertHexTodec(prefix_temp);
				
				memcpy(buff , str+i+1+1+2 , data_len);
				buff[data_len]='\0';
				
				char2hex(buff,temp,data_len);
				
				for(k=0;k<strlen(temp);k+=4)
				{
					memcpy(ipv6_temp1+len , temp+k , 4);	len+=4;
					ipv6_temp1[len++]=':';
				}
				
				memcpy(ipv6_temp2 , ipv6_temp1 , len-1);
				
				if((UI)(str[i])!=26)
				{
					printf("%s = %s/%lld\n",radius_attr[j].attribute,ipv6_temp2,value); fflush(stdout);
					
					sprintf((char*)output,"%s/%lld",ipv6_temp2,value);
					
					ht_insert(ht, radius_attr[j].attribute, output);
				}
				break;
			}
		}
		
        i+=Val_len;
	}
	
	Save_data_Into_Mysql();
    
    //~ printf("\n\n"); fflush(stdout);
	//~ print_table(ht); fflush(stdout);
    
    free_table(ht);
}

int Check_session_ID(UC * acctsessionid , MYSQL *con)
{
	int val			=	0;
	int num_fields	=	0;
	int i			=	0;
	
	UC fetchquery [500] = {0};
	
	MYSQL_ROW row;
	MYSQL_RES *result;
	
	sprintf((char*)fetchquery , "SELECT COUNT(acctsessionid) FROM radacct WHERE acctsessionid = '%s'",acctsessionid);
	printf("\nSession fetchquery : %s\n",fetchquery); fflush(stdout);
	
	if (mysql_query(con, fetchquery))
	{
		finish_with_error(con);
	}
	
	result = mysql_store_result(con);
	if (result == NULL)
	{
		finish_with_error(con);
	}
	
	num_fields = mysql_num_fields(result);
	
	while ((row = mysql_fetch_row(result)))
	{
		for(i = 0; i < num_fields; i++)
		{
			val = atoi(row[i] ? row[i] : "0");
		}
	}
	
	printf("\nSession ID found : %d\n",val); fflush(stdout);
	
	mysql_free_result(result);
	
	return val;
}

void delete_create_table(MYSQL *con)
{
	if (mysql_query(con, "DROP TABLE IF EXISTS radacct"))
	{
		finish_with_error(con);
	}
	
	if (mysql_query(con, "CREATE TABLE radacct ( \
		radacctid bigint(21) NOT NULL auto_increment, \
		acctsessionid varchar(64) NOT NULL default '',\
		acctuniqueid varchar(32) NOT NULL default '',\
		username varchar(64) NOT NULL default '',\
		groupname varchar(64) NOT NULL default '',\
		realm varchar(64) default '',\
		nasipaddress varchar(15) NOT NULL default '',\
		nasportid varchar(50) default NULL,\
		nasporttype varchar(32) default NULL,\
		nasidentifier varchar(32) default NULL,\
		acctstarttime datetime NULL default NULL,\
		acctupdatetime datetime NULL default NULL,\
		acctstoptime datetime NULL default NULL,\
		acctinterval int(12) default NULL,\
		acctsessiontime int(12) unsigned default NULL,\
		acctauthentic varchar(32) default NULL,\
		connectinfo_start varchar(50) default NULL,\
		connectinfo_stop varchar(50) default NULL,\
		acctinputoctets bigint(20) default NULL,\
		acctoutputoctets bigint(20) default NULL,\
		calledstationid varchar(50) NOT NULL default '',\
		callingstationid varchar(50) NOT NULL default '',\
		acctterminatecause varchar(32) NOT NULL default '',\
		servicetype varchar(32) default NULL,\
		framedprotocol varchar(32) default NULL,\
		framedipaddress varchar(15) NOT NULL default '',\
		delegatedipv6prefix varchar(50) NOT NULL default '',\
        MCC varchar(32) default NULL,\
        MNC varchar(32) default NULL,\
        LAC int(12) default NULL,\
        SAC int(12) default NULL,\
		PRIMARY KEY (radacctid),\
		UNIQUE KEY acctuniqueid (acctuniqueid),\
		KEY username (username),\
		KEY framedipaddress (framedipaddress),\
		KEY acctsessionid (acctsessionid),\
		KEY acctsessiontime (acctsessiontime),\
		KEY acctstarttime (acctstarttime),\
		KEY acctinterval (acctinterval),\
		KEY acctstoptime (acctstoptime),\
		KEY nasipaddress (nasipaddress),\
		KEY framedipv6prefix (delegatedipv6prefix)\
		)"))
	{
		finish_with_error(con);
	}
}

void Save_data_Into_Mysql()
{
	int datalen		=	0;
	int found 		=	0;
	
	UC buff					[1024]	=	{0};
	UC query				[4096]	=	{0};
	UC acct_type_buf		[20]	=	{0};
	UC nasport				[100]	=	{0};
	UC acctsessionid		[100]	=	{0};
	UC acctuniqueid         [100]	=	{0};		// Combination of values of "User-Name, Acct-Session-Id, NAS-IP-Address, NAS-Port" ( 1 + 44 + 4 + 5 )
	UC username             [100]	=	{0};
	UC realm                [100]	=	{0};
	UC nasipaddress         [100]	=	{0};
	UC nasportid            [100]	=	{0};
	UC nasporttype          [100]	=	{0};
	UC nasidentifier        [100]	=	{0};
	UC acctstarttime        [100]	=	{0};
	UC acctupdatetime       [100]	=	{0};
	UC acctstoptime         [100]	=	{0};
	UC acctsessiontime      [100]	=	{0};
	UC acctauthentic        [100]	=	{0};
	UC connectinfo_start    [100]	=	{0};
	UC connectinfo_stop     [100]	=	{0};
	UC acctinputoctets      [100]	=	{0};
	UC acctoutputoctets     [100]	=	{0};
	UC calledstationid      [100]	=	{0};
	UC callingstationid     [100]	=	{0};
	UC acctterminatecause   [100]	=	{0};
	UC servicetype          [100]	=	{0};
	UC framedprotocol       [100]	=	{0};
	UC framedipaddress      [100]	=	{0};
	UC framedipv6prefix  	[100]	=	{0};
	UC delegatedipv6prefix 	[100]	=	{0};
	UC acctInputGigawords  	[100]	=	{0};
	UC acctOnputGigawords  	[100]	=	{0};
	UC MCC  	            [100]	=	{0};
	UC MNC  	            [100]	=	{0};
	UC LAC  	            [100]	=	{0};
	UC SAC  	            [100]	=	{0};
	
	char server				[16] 	=	"localhost";
	char user				[16] 	=	"root";
	char password			[16] 	=	"testing@123";
	char database			[16] 	=	"mydb";
	
	MYSQL *con = mysql_init(NULL);
	if (con == NULL)
	{
		fprintf(stderr, "%s\n", mysql_error(con));
		exit(1);
	}
    
	if (mysql_real_connect(con, server, user , password, database, 0, NULL, 0) == NULL)
	{
		finish_with_error(con);
	}
    
	// Delete and create existing table (for testing purposes)
	//~ delete_create_table(con);
	
	//~ printf("\n\n"); fflush(stdout);
	//~ print_table(ht); fflush(stdout);
	
	print_search(ht, "Acct-Status-Type" 		, acct_type_buf);
	print_search(ht, "User-Name" 				, username);
	print_search(ht, "Acct-Session-Id" 			, acctsessionid);
	print_search(ht, "NAS-IP-Address" 			, nasipaddress);
	print_search(ht, "NAS-Port" 				, nasport);
	print_search(ht, "NAS-Port-Id" 				, nasportid);
	print_search(ht, "NAS-Port-Type" 			, nasporttype);
	print_search(ht, "Event-Timestamp" 			, acctstarttime);
	print_search(ht, "Event-Timestamp" 			, acctstoptime);
	print_search(ht, "Event-Timestamp" 			, acctupdatetime);
	print_search(ht, "Acct-Session-Time" 		, acctsessiontime);
	print_search(ht, "Acct-Authentic" 			, acctauthentic);
	print_search(ht, "Acct-Input-Octets" 		, acctinputoctets);
	print_search(ht, "Acct-Output-Octets" 		, acctoutputoctets);
	print_search(ht, "Acct-Terminate-Cause" 	, acctterminatecause);
	print_search(ht, "Service-Type" 			, servicetype);
	print_search(ht, "Framed-Protocol" 			, framedprotocol);
	print_search(ht, "Framed-Protocol" 			, framedipaddress);
	print_search(ht, "Framed-IP-Address" 		, framedipaddress);
	print_search(ht, "Connect-Info" 			, connectinfo_start);
	print_search(ht, "Connect-Info" 			, connectinfo_stop);
	print_search(ht, "Calling-Station-Id"		, callingstationid);
	print_search(ht, "Called-Station-Id" 		, calledstationid);
	print_search(ht, "NAS-Identifier" 			, nasidentifier);
	print_search(ht, "Framed-IPv6-Prefix" 		, framedipv6prefix);
	print_search(ht, "Delegated-IPv6-Prefix" 	, delegatedipv6prefix);
	print_search(ht, "Acct-Input-Gigawords" 	, acctInputGigawords);
	print_search(ht, "Acct-Output-Gigawords" 	, acctOnputGigawords);
    print_search(ht, "Mobile Country Code"      , MCC);
    print_search(ht, "Mobile Network Code"      , MNC);
    print_search(ht, "Location Area Code"       , LAC);
    print_search(ht, "Service Area Code"        , SAC);
    
	
	// acctuniqueid is a combination of the MD5 hash output of ->
	// 1. User-Name
	// 2. Acct-Session-Id
	// 3. NAS-IP-Address
	// 4. NAS-Port
	
	sprintf((char*)buff,"%s%s%s%s",username,acctsessionid,nasipaddress,nasport);
	//~ printf("\n\nbuffer : %s\n",buff); fflush(stdout);
	
	bytes2md5(buff, strlen(buff), acctuniqueid);
	printf("\n\nacctuniqueid : %s\n", acctuniqueid); fflush(stdout);
	
	printf("\nacct_type_buf : %s\n",acct_type_buf); fflush(stdout);
	
	memset(query,0x00,sizeof(query));
	
	found = Check_session_ID(acctsessionid , con);
	
	if(strcmp(acct_type_buf , "Start")==0)
	{
		if(found == 1)
		{
			sprintf((char*)query , "UPDATE radacct SET acctstarttime = FROM_UNIXTIME(%s) , acctupdatetime = FROM_UNIXTIME(%s) , connectinfo_start = '%s' WHERE acctsessionid = '%s'",
						acctstarttime,
						acctupdatetime,
						connectinfo_start,
						acctsessionid
					);
			
			printf("\nStart updatequery is \"%s\"\n",query); fflush(stdout);
		}
		else
		{
			sprintf((char*)query , (const char*)"INSERT INTO radacct (acctsessionid,acctuniqueid,username,realm,nasipaddress,nasportid,nasporttype,acctstarttime,acctupdatetime,acctstoptime,acctsessiontime,acctauthentic,connectinfo_start,connectinfo_stop,acctinputoctets,acctoutputoctets,calledstationid,callingstationid,acctterminatecause,servicetype,framedprotocol,framedipaddress,nasidentifier,delegatedipv6prefix,MCC,MNC,LAC,SAC) VALUES ('%s' , '%s' , '%s' , '%c' , '%s' , '%s' , '%s' , FROM_UNIXTIME(%s) , FROM_UNIXTIME(%s) , FROM_UNIXTIME(%s) , '%c' , '%s' , '%s' , '%c' , '%c' , '%c' , '%s' , '%s' , '%c' , '%s' , '%s' , '%s' , '%s' , '%s' , '%s' , '%s' , '%s' , '%s')",
						acctsessionid,
						acctuniqueid,
						username,
						' ',
						nasipaddress,
						nasportid,
						nasporttype,
						acctstarttime,
						acctupdatetime,
						"NULL",
						'0',
						acctauthentic,
						connectinfo_start,
						' ',
						'0',
						'0',
						calledstationid,
						callingstationid,
						' ',
						servicetype,
						framedprotocol,
						framedipaddress,
						nasidentifier,
						delegatedipv6prefix,
                        MCC,
                        MNC,
                        LAC,
                        SAC
				);
			
			printf("\nStart insertquery is \"%s\"\n",query); fflush(stdout);
		}
	}
	else if(strcmp(acct_type_buf , "Stop")==0)
	{
		if(found == 1)
		{
			sprintf((char*)query , "UPDATE radacct SET acctstoptime = FROM_UNIXTIME(%s) , acctsessiontime = '%s' , acctinputoctets = '%s' , acctoutputoctets = '%s' , acctterminatecause = '%s' , connectinfo_stop = '%s' WHERE acctsessionid = '%s'",
						acctstoptime,
						acctsessiontime,
						acctinputoctets,
						acctoutputoctets,
						acctterminatecause,
						connectinfo_stop,
						acctsessionid
					);
			
			printf("\nStop updatequery is \"%s\"\n",query); fflush(stdout);
		}
		else
		{
			sprintf((char*)query , "INSERT INTO radacct (acctsessionid,acctuniqueid,username,realm,nasipaddress,nasportid,nasporttype,acctstarttime,acctupdatetime,acctstoptime,acctsessiontime,acctauthentic,connectinfo_start,connectinfo_stop,acctinputoctets,acctoutputoctets,calledstationid,callingstationid,acctterminatecause,servicetype,framedprotocol,framedipaddress,nasidentifier,delegatedipv6prefix,MCC,MNC,LAC,SAC) VALUES ('%s' , '%s' , '%s' , '%c' , '%s' , '%s' , '%s' , FROM_UNIXTIME(%s - %s) , FROM_UNIXTIME(%s) , FROM_UNIXTIME(%s) ,'%s' , '%s' , '%c' , '%c' , '%s' , '%s' , '%s' , '%s' , '%s' , '%s' , '%s' , '%s' , '%s' , '%s' , '%s' , '%s' , '%s' , '%s')",
						acctsessionid,
						acctuniqueid,
						username,
						' ',
						nasipaddress,
						nasportid,
						nasporttype,
						acctstarttime,
						acctsessiontime,
						acctupdatetime,
						acctstoptime,
						acctsessiontime,
						acctauthentic,
						' ',
						' ',
						acctinputoctets,
						acctoutputoctets,
						calledstationid,
						callingstationid,
						acctterminatecause,
						servicetype,
						framedprotocol,
						framedipaddress,
						nasidentifier,
						delegatedipv6prefix,
                        MCC,
                        MNC,
                        LAC,
                        SAC
			);
			
			printf("\nStop insertquery is \"%s\"\n",query); fflush(stdout);
		}
	}
	
	if (mysql_query(con, query))
	{
		finish_with_error(con);
	}
	
    mysql_close(con);
}

void finish_with_error(MYSQL *con)
{
	fprintf(stderr, "%s\n", mysql_error(con));
	mysql_close(con);
	exit(1);
}

void print_udp_packet(UC *Buffer , int Size)
{
	US iphdrlen;
	struct iphdr *iph;
	struct udphdr *udph;
	int header_size;
	int datalen=0;
    
	UC temp[65536]={0};
	
	if(UDP==1)
		iph = (struct iphdr *)Buffer;
	else
		iph = (struct iphdr *)(Buffer +  sizeof(struct ethhdr));
	
	iphdrlen = iph->ihl*4;
	
	if(UDP==1)
		udph = (struct udphdr*)(Buffer + iphdrlen);
	else
		udph = (struct udphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));
	
	header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof udph;
	
	if(ntohs(udph->dest) == PORT)
	{
		send4Debug(0,Buffer, Size);
		
		//~ printf("\n\n***********************UDP Packet*************************\n");fflush(stdout);
		
		//~ if(SAVE_DATA == 1)
			//~ fprintf(logfile , "\n\n***********************UDP Packet*************************\n");
		
		//~ print_ip_header(Buffer,Size);
		
		//~ if(SAVE_DATA == 1)
		//~ {
			//~ fprintf(logfile , "\nUDP Header\n");
			//~ fprintf(logfile , "   |-Source Port      : %d\n" , ntohs(udph->source));
			//~ fprintf(logfile , "   |-Destination Port : %d\n" , ntohs(udph->dest));
			//~ fprintf(logfile , "   |-UDP Length       : %d\n" , ntohs(udph->len));
			//~ fprintf(logfile , "   |-UDP Checksum     : %d\n" , ntohs(udph->check));
		//~ }
		
		//~ printf("\nUDP Header\n"); fflush(stdout);                                      fflush(stdout);
		//~ printf("   |-Source Port      : %d\n" , ntohs(udph->source));fflush(stdout);   fflush(stdout);
		//~ printf("   |-Destination Port : %d\n" , ntohs(udph->dest));fflush(stdout);     fflush(stdout);
		//~ printf("   |-UDP Length       : %d\n" , ntohs(udph->len));fflush(stdout);      fflush(stdout);
		//~ printf("   |-UDP Checksum     : %d\n" , ntohs(udph->check));fflush(stdout);    fflush(stdout);
		
		//~ printf("\n"); fflush(stdout);
		//~ printf("IP Header\n"); fflush(stdout);
		
		//~ if(SAVE_DATA == 1)
		//~ {
			//~ fprintf(logfile , "\n");
			//~ fprintf(logfile , "IP Header\n");
		//~ }
		
		//~ PrintData(Buffer , iphdrlen);
			
		//~ printf("UDP Header\n"); fflush(stdout);
		
		//~ if(SAVE_DATA == 1)
			//~ fprintf(logfile , "UDP Header\n");
		
		//~ PrintData(Buffer+iphdrlen , sizeof udph);
		
		//~ printf("Data Payload\n"); fflush(stdout);
		
		if(SAVE_DATA == 1)
			fprintf(logfile , "Data Payload\n");
		
		//Move the pointer ahead and reduce the size of string
        switch(PROTOCOL)
        {
            case 'R':   // Radius Protocol
                        if(UDP==1)
                        {
                            datalen = (Size - sizeof udph - iph->ihl * 4) - 20;
                            PrintData(Buffer + iphdrlen + sizeof udph ,datalen);
                            memcpy(temp , Buffer + iphdrlen + sizeof udph + 20 , datalen);
                            Fetch_Radius_Attributes(temp , datalen);
                        }
                        else
                        {
                            datalen = Size - header_size - 20;
                            PrintData(Buffer + header_size , datalen);
                            memcpy(temp , Buffer + header_size + 20 , datalen);
                            Fetch_Radius_Attributes(temp , datalen);
                        }
                        break;
                        
            case 'G':   // GTP protocol
                        if(UDP==1)
                        {
                            datalen = Size - header_size;
                            memcpy(temp , Buffer + header_size , datalen);
                            Fetch_GTP_Data(temp , datalen);
                        }
                        else
                        {
                            datalen = (Size - sizeof udph - iph->ihl * 4);
                            memcpy(temp , Buffer + iphdrlen + sizeof udph , datalen);
                            Fetch_GTP_Data(temp , datalen);
                        }
                        break;
        }
		
		//~ printf("\n###########################################################\n");   fflush(stdout);
		
		if(SAVE_DATA == 1)
			fprintf(logfile , "\n###########################################################");
	}
}

void print_icmp_packet(UC* Buffer , int Size)
{
	US iphdrlen;
	struct iphdr *iph;
	struct icmphdr *icmph;
	int header_size;
	
	if(UDP==1)
		iph = (struct iphdr *)Buffer;
	else
		iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr));
	
	iphdrlen = iph->ihl * 4;
	
	if(UDP==1)
		icmph = (struct icmphdr *)(Buffer + iphdrlen);
	else
		icmph = (struct icmphdr *)(Buffer + iphdrlen  + sizeof(struct ethhdr));
	
	header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof icmph;
	
	if(SAVE_DATA == 1)
		fprintf(logfile , "\n\n***********************ICMP Packet*************************\n");	
	
	printf("\n\n***********************ICMP Packet*************************\n");     fflush(stdout);	
	
	print_ip_header(Buffer , Size);
	
	if(SAVE_DATA == 1)
	{
		fprintf(logfile , "\n");
        
		fprintf(logfile , "ICMP Header\n");
		fprintf(logfile , "   |-Type : %d",(UI)(icmph->type));
	}
	
	printf("\n");    fflush(stdout);
    
	printf("ICMP Header\n");  fflush(stdout);
	printf("   |-Type : %d",(UI)(icmph->type)); fflush(stdout);
    
	if((UI)(icmph->type) == 11)
	{
		if(SAVE_DATA == 1)
			fprintf(logfile , "  (TTL Expired)\n");
        
		printf("  (TTL Expired)\n"); fflush(stdout);
	}
	else if((UI)(icmph->type) == ICMP_ECHOREPLY)
	{
		if(SAVE_DATA == 1)
			fprintf(logfile , "  (ICMP Echo Reply)\n");
		
		printf("  (ICMP Echo Reply)\n"); fflush(stdout);
	}
	
	if(SAVE_DATA == 1)
	{
		fprintf(logfile , "   |-Code : %d\n",(UI)(icmph->code));
		fprintf(logfile , "   |-Checksum : %d\n",ntohs(icmph->checksum));
		fprintf(logfile , "\n");
        
		fprintf(logfile , "IP Header\n");
	}
	
	printf("   |-Code : %d\n",(UI)(icmph->code)); fflush(stdout);
	printf("   |-Checksum : %d\n",ntohs(icmph->checksum)); fflush(stdout);
	printf("\n"); fflush(stdout);
	
	printf("IP Header\n"); fflush(stdout);
    
	PrintData(Buffer,iphdrlen);
	
	if(SAVE_DATA == 1)
		fprintf(logfile , "UDP Header\n");
	
	printf("UDP Header\n"); fflush(stdout);
    
	PrintData(Buffer + iphdrlen , sizeof icmph);
	
	if(SAVE_DATA == 1)
		fprintf(logfile , "Data Payload\n");	
	
	printf("Data Payload\n"); fflush(stdout);
	
	//Move the pointer ahead and reduce the size of string
	if(UDP==1)
		PrintData(Buffer + iphdrlen + sizeof icmph , (Size - sizeof icmph - iph->ihl * 4));
	else
		PrintData(Buffer + header_size , (Size - header_size) );
	
	if(SAVE_DATA == 1)
		fprintf(logfile , "\n###########################################################");
	
	printf("\n###########################################################"); fflush(stdout);
}

void PrintData (UC* data , int Size)
{
	int i , j;
	
	for(i=0 ; i < Size ; i++)
	{
		if( i!=0 && i%16==0)   //if one line of hex printing is complete...
		{
			if(SAVE_DATA == 1)
				fprintf(logfile , "         ");
			
			printf("         ");  fflush(stdout);
			
			for(j=i-16 ; j<i ; j++)
			{
				if(data[j]>=32 && data[j]<=128)
				{
					if(SAVE_DATA == 1)
						fprintf(logfile , "%c",(UC)data[j]); //if its a number or alphabet
					
					printf("%c",(UC)data[j]); fflush(stdout);
				}
				else
				{
					if(SAVE_DATA == 1)
						fprintf(logfile , "."); //otherwise print a dot
					
					printf(".");  fflush(stdout);
				}
			}
			
			if(SAVE_DATA == 1)
				fprintf(logfile , "\n");
			
			printf("\n"); fflush(stdout);
		}
		
		if(i%16==0)
		{
			if(SAVE_DATA == 1)
				fprintf(logfile , "   ");
			
			printf("   "); fflush(stdout);
		}
		
		if(SAVE_DATA == 1)
			fprintf(logfile , " %02X",(UI)data[i]);
		
		printf(" %02X",(UI)data[i]); fflush(stdout);
		
		if( i==Size-1)  //print the last spaces
		{
			for(j=0;j<15-i%16;j++) 
			{
				if(SAVE_DATA == 1)
					fprintf(logfile , "   "); //extra spaces
				
				printf("   ");  fflush(stdout);
			}
			
			if(SAVE_DATA == 1)
				fprintf(logfile , "         ");
			
			printf("         "); fflush(stdout);
			
			for(j=i-i%16 ; j<=i ; j++)
			{
				if(data[j]>=32 && data[j]<=128) 
				{
					if(SAVE_DATA == 1)
						fprintf(logfile , "%c",(UC)data[j]);
					
					printf("%c",(UC)data[j]); fflush(stdout);
				}
				else 
				{
					if(SAVE_DATA == 1)
						fprintf(logfile , ".");
					
					printf("."); fflush(stdout);
				}
			}
			
			if(SAVE_DATA == 1)
				fprintf(logfile ,  "\n" );
			
			printf("\n" ); fflush(stdout);
		}
	}
}

Ht_item* create_item(char* key, char* value)
{
    // Creates a pointer to a new hash table item
    Ht_item* item = (Ht_item*) malloc (sizeof(Ht_item));
    
    item->key = (char*) malloc (strlen(key) + 1);
    item->value = (char*) malloc (strlen(value) + 1);
     
    strcpy(item->key, key);
    strcpy(item->value, value);
 
    return item;
}

HashTable* create_table(int size)
{
    int i=0;
    
    // Creates a new HashTable
    HashTable* table = (HashTable*) malloc (sizeof(HashTable));
    table->size = size;
    table->count = 0;
    table->items = (Ht_item**) calloc (table->size, sizeof(Ht_item*));
    for (i=0; i<table->size; i++)
        table->items[i] = NULL;
 
    return table;
}

void free_item(Ht_item* item)
{
    // Frees an item
    free(item->key);
    free(item->value);
    free(item);
}

void free_table(HashTable* table)
{
    int i=0;
    
    // Frees the table
    for (i=0; i<table->size; i++) {
        Ht_item* item = table->items[i];
        if (item != NULL)
            free_item(item);
    }
 
    free(table->items);
    free(table);
}

void handle_collision(HashTable* table, UL index, Ht_item* item)
{

}

void ht_insert(HashTable* table, char* key, char* value)
{
	Ht_item* current_item;
	Ht_item* item;
	UL index;
    
    UC Keybuf[100]={0};
    
    strcpy(Keybuf   ,   key);
    
here:
	
	// Create the item
	item = create_item(Keybuf, value);
	
	// Compute the index
	index = hash_function(Keybuf);
    
	current_item = table->items[index];
    if (current_item == NULL) 
    {
		//printf("\nindex : %ld\n",index); fflush(stdout);
		
        // Key does not exist.
        if (table->count == table->size)
        {
            // Hash Table Full
            printf("Insert Error: Hash Table is full\n");	fflush(stdout);
            // Remove the create item
            free_item(item);
            return;
        }
         
        // Insert directly
        table->items[index] = item;
        
        //printf("\ntable->items[%ld] : %s item : %s\n\n",index , table->items[index]->value,item->value); fflush(stdout);
        
        table->count++;
    }
    else
    {
		// Scenario 1: We only need to update value
		if (strcmp(current_item->key, Keybuf) == 0)
		{
			//~ strcpy(table->items[index]->value, value);
			
			//~ printf("\nSame data table->items[%ld]->value : %s item : %s\n\n",index,table->items[index]->value , value); fflush(stdout);
			
            strcat(Keybuf , "_2");
            goto here;
            
			//~ return;
		}
        else
        {
            // Scenario 2: Collision
            // We will handle case this a bit later
            handle_collision(table, index, item);
            return;
        }
    }
}

UC* ht_search(HashTable* table, char* key)
{
    // Searches the key in the hashtable
    // and returns NULL if it doesn't exist
    int index = hash_function(key);
    Ht_item* item = table->items[index];
    
    // Ensure that we move to a non NULL item
    if (item != NULL)
    {
        if (strcmp(item->key, key) == 0)
            return item->value;
    }
    return NULL;
}

void print_search(HashTable* table, char* key , UC* val)
{
	UC *value;
	
    if ((value = ht_search(table, key)) == NULL)
    {
        //~ printf("Key:%s does not exist\n", key);	fflush(stdout);
        return;
    }
    else
    {
        //~ printf("\nKey:%s, Value:%s[%ld]\n", key, value,strlen(value));	fflush(stdout);
        
        strcpy(val , value);
    }
}

void print_table(HashTable* table)
{
	int i=0;
	
    printf("\nHash Table\n-------------------\n\n");	fflush(stdout);
    
    for (i=0; i<table->size; i++) 
    {
        if (table->items[i])
        {
            printf("Index:%d\tKey:%s\tValue:%s\n", i, table->items[i]->key, table->items[i]->value);	fflush(stdout);
        }
    }
    printf("-------------------\n\n");	fflush(stdout);
}

UL hash_function(char* str)
{
    UL i = 0;
    int j=0;
    
    for (j=0; str[j]; j++)
        i += str[j];
    return i % CAPACITY;
}

int main()
{
	int saddr_size , data_size;
	int i=0;
	int sock_raw;
	struct sockaddr saddr;
	struct sockaddr_in daddr;
		
	UC *buffer = (UC *) malloc(65536); //Its Big!
	
	if(SAVE_DATA == 1)
	{
		logfile=fopen("log.txt","w");
		if(logfile==NULL) 
		{
			printf("Unable to create log.txt file.");	fflush(stdout);
		}
	}
	
	printf("\nStarting...\n\n");	fflush(stdout);
	
	if(UDP==1)
	{
		sock_raw = socket(AF_INET , SOCK_RAW , IPPROTO_UDP);
		
		//~ memset((char *)&daddr,0,sizeof(daddr));
        
		//~ //prepare the sockaddr_in structure
		//~ daddr.sin_family = AF_INET;
		//~ daddr.sin_addr.s_addr = htonl(INADDR_ANY);
		//~ daddr.sin_port = htons(PORT);
		
		//~ //Bind
		//~ if(bind(sock_raw,(struct sockaddr *)&daddr, sizeof(daddr))<0)
		//~ {
		  //~ printf("bind failed"); fflush(stdout);
		  //~ return 1;
		//~ }
		//~ printf("bind done\n"); fflush(stdout);
	}
	else
	{
		// Socket to Sniff both incoming and outgoing traffic.
		sock_raw = socket(AF_PACKET , SOCK_RAW , htons(ETH_P_ALL)) ;
	}
	
	//~ setsockopt(sock_raw , SOL_SOCKET , SO_BINDTODEVICE , "eth0" , strlen("eth0")+ 1 );
	
	if(sock_raw < 0)
	{
		//Print the error with proper message
		perror("Socket Error");	fflush(stdout);
		return 1;
	}
	
	while(1)
	{
		saddr_size = sizeof saddr;
		
		//Receive a packet
		data_size = recvfrom(sock_raw , buffer , 65536 , 0 , &saddr , (socklen_t*)&saddr_size);
		if(data_size < 0)
		{
			printf("Recvfrom error , failed to get packets\n");	fflush(stdout);
			return 1;
		}
		
		//Now process the packet
		ProcessPacket(buffer , data_size);
	}
	
	fclose(logfile);
	close(sock_raw);
	
    printf("Finished");	fflush(stdout);
	
    return 0;
}
