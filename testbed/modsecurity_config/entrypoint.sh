#!/bin/sh
# Fix permissions for nginx log directory
chown -R nginx:nginx /var/log/nginx
chmod -R 755 /var/log/nginx

# Execute the original entrypoint
exec /docker-entrypoint.sh "$@"
