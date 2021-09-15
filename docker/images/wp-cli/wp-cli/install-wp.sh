#!/usr/bin/env sh


echo $NODE_IP
# Install WordPress.
wp --allow-root core install \
  --title="Damn Vulnerable WordPress" \
  --admin_user="admin" \
  --admin_password="admin" \
  --admin_email="admin@example.com" \
  --url="http://${NODE_IP}" \
  --skip-email
# Update permalink structure.
# wp option update permalink_structure "/%year%/%monthnum%/%postname%/" --skip-themes --skip-plugins

# Activate plugin.
wp --allow-root plugin activate iwp-client
wp --allow-root plugin activate social-warfare
wp --allow-root plugin activate wp-advanced-search
wp --allow-root  plugin activate wp-file-upload
# wp plugin activate wp-time-capsule # Causes error

# Update DB
wp --allow-root  db import dump.sql

while true;
do
	sleep 3
done

