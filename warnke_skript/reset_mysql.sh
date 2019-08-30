#!/bin/bash

echo $1
echo $2

if [ -z "$1" ]
then
	datadir="/var/lib/mysql"
else
	datadir="$1"
fi
echo ${datadir}

cat << EOF > /etc/mysql/mariadb.conf.d/50-server.cnf
[mysqld]
innodb_file_per_table   = 0
user                    = mysql
pid-file                = /run/mysqld/mysqld.pid
socket                  = /run/mysqld/mysqld.sock
basedir                 = /usr
datadir                 = ${datadir}
tmpdir                  = /tmp
lc-messages-dir         = /usr/share/mysql
bind-address            = 127.0.0.1
query_cache_size        = 16M
log_error               = /var/log/mysql/error.log
expire_logs_days        = 10
character-set-server    = utf8mb4
collation-server        = utf8mb4_general_ci
EOF

systemctl stop mysqld
rm -rf ${datadir}
chmod -R 777 /mnt2
mysql_install_db
systemctl start mysqld
mysql --user='root' -e "ALTER USER 'root'@'localhost' IDENTIFIED BY '1234'"
mysql --user='root' --password='1234' -e "CREATE DATABASE julea"


