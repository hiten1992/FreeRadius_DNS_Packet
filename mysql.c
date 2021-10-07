#include <mysql.h>
#include <stdio.h>
#include <stdlib.h>

// CREATE USER 'root'@'localhost' IDENTIFIED BY 'testing@123';

// DROP USER 'root'@'localhost';

// delete from user where user='root'and host='localhost';

// GRANT ALL PRIVILEGES ON *.* TO 'root'@'localhost' IDENTIFIED BY 'testing@123';

// SHOW DATABASES;

// To uninstall mysql from laptop-->>
//	1. sudo systemctl stop mysql
//	2. sudo apt-get purge mysql-server mysql-client mysql-common mysql-server-core-* mysql-client-core-*
//	3. sudo rm -rf /etc/mysql /var/lib/mysql
//	4. sudo apt autoremove
//	5. sudo apt autoclean

void finish_with_error(MYSQL *con)
{
	printf("\n111111\n"); fflush(stdout);
	fprintf(stderr, "%s\n", mysql_error(con));
	mysql_close(con);
	exit(1);
}

int main(int argc, char **argv)
{
	char server[16] = "localhost";
	char username[16] = "root";
	char password[16] = "testing@123";
	char database[16] = "mydb";
    
	MYSQL *con = mysql_init(NULL);

	if (con == NULL)
	{
		fprintf(stderr, "%s\n", mysql_error(con));
		exit(1);
	}

	if (mysql_real_connect(con, server, username, password, database, 0, NULL, 0) == NULL)
	{
		finish_with_error(con);
	}

	if (mysql_query(con, "DROP TABLE IF EXISTS testing"))
	{
		finish_with_error(con);
	}

	//~ if (mysql_query(con, "CREATE TABLE testing(id INT PRIMARY KEY AUTO_INCREMENT, name VARCHAR(255), price INT)"))
	//~ {
		//~ finish_with_error(con);
	//~ }
	
	if (mysql_query(con, "CREATE TABLE testing ( \
		  radacctid bigint(21) NOT NULL auto_increment, \
		  acctsessionid varchar(64) NOT NULL default '',\
		  acctuniqueid varchar(32) NOT NULL default '',\
		  username varchar(64) NOT NULL default '',\
		  groupname varchar(64) NOT NULL default '',\
		  realm varchar(64) default '',\
		  nasipaddress varchar(15) NOT NULL default '',\
		  nasportid varchar(50) default NULL,\
		  nasporttype varchar(32) default NULL,\
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
		  PRIMARY KEY (radacctid),\
		  UNIQUE KEY acctuniqueid (acctuniqueid),\
		  KEY username (username),\
		  KEY framedipaddress (framedipaddress),\
		  KEY acctsessionid (acctsessionid),\
		  KEY acctsessiontime (acctsessiontime),\
		  KEY acctstarttime (acctstarttime),\
		  KEY acctinterval (acctinterval),\
		  KEY acctstoptime (acctstoptime),\
		  KEY nasipaddress (nasipaddress)\
		)"))
	{
		finish_with_error(con);
	}

	//~ if (mysql_query(con, "INSERT INTO testing VALUES(1,'Audi',52642)"))
	//~ {
		//~ finish_with_error(con);
	//~ }
	
	printf("\ndata inserted successfully..\n"); fflush(stdout);
	
	mysql_close(con);
}
