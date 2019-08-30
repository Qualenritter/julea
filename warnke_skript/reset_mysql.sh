systemctl stop mysqld
rm -rf /var/lib/mysql
mysql_install_db
systemctl start mysqld
mysql --user='root' -e "ALTER USER 'root'@'localhost' IDENTIFIED BY '1234'"
mysql --user='root' --password='1234' -e "CREATE DATABASE julea"
