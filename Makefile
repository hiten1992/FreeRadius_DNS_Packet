all:
	gcc -o dns_sniffer dns_sniffer.c -lpcap  -lm
	gcc -o dns_host dns_host.c -lpcap  -lm
	gcc -o dns_udp dns_udp.c -lpcap  -lm -lssl -lcrypto `mysql_config --cflags --libs`
	gcc -o simpleudp simpleudp.c -lpcap  -lm
	gcc -o mysql mysql.c `mysql_config --cflags --libs`
clean:
	rm dns_sniffer dns_host dns_udp simpleudp mysql
 
