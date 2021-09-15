#!/usr/bin/env sh


ls
whoami 
id -u xfs 
echo $NODE_IP
# Install WordPress.
wp core install \
  --title="Damn Vulnerable WordPress" \
  --admin_user="admin" \
  --admin_password="admin" \
  --admin_email="admin@example.com" \
  --url="http://${NODE_IP}:30050" \
  --skip-email

# Update permalink structure.
# wp option update permalink_structure "/%year%/%monthnum%/%postname%/" --skip-themes --skip-plugins

# Activate plugin.
wp plugin activate iwp-client 
wp plugin activate social-warfare 
wp plugin activate wp-advanced-search 
wp plugin activate wp-file-upload 
# wp plugin activate wp-time-capsule # Causes error

# Update DB
wp db import dump.sql

while true;
do
	sleep 3
done

