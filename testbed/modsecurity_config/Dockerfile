FROM owasp/modsecurity-crs:nginx-alpine

# Override nginx config to write logs to files instead of stdout/stderr
RUN echo 'server_tokens off;' > /etc/nginx/conf.d/default.conf && \
    echo '' >> /etc/nginx/conf.d/default.conf && \
    echo 'map $http_upgrade $connection_upgrade {' >> /etc/nginx/conf.d/default.conf && \
    echo '    default upgrade;' >> /etc/nginx/conf.d/default.conf && \
    echo '    '\'''\'' close;' >> /etc/nginx/conf.d/default.conf && \
    echo '}' >> /etc/nginx/conf.d/default.conf && \
    echo '' >> /etc/nginx/conf.d/default.conf && \
    echo 'server {' >> /etc/nginx/conf.d/default.conf && \
    echo '    listen 8080 default_server;' >> /etc/nginx/conf.d/default.conf && \
    echo '    server_name localhost;' >> /etc/nginx/conf.d/default.conf && \
    echo '    set $always_redirect off;' >> /etc/nginx/conf.d/default.conf && \
    echo '' >> /etc/nginx/conf.d/default.conf && \
    echo '    access_log /var/log/nginx/access.log;' >> /etc/nginx/conf.d/default.conf && \
    echo '    error_log /var/log/nginx/error.log;' >> /etc/nginx/conf.d/default.conf && \
    echo '' >> /etc/nginx/conf.d/default.conf && \
    echo '    location / {' >> /etc/nginx/conf.d/default.conf && \
    echo '        client_max_body_size 0;' >> /etc/nginx/conf.d/default.conf && \
    echo '        if ($always_redirect = on) {' >> /etc/nginx/conf.d/default.conf && \
    echo '            return 301 https://$host$request_uri;' >> /etc/nginx/conf.d/default.conf && \
    echo '        }' >> /etc/nginx/conf.d/default.conf && \
    echo '        include includes/cors.conf;' >> /etc/nginx/conf.d/default.conf && \
    echo '        include includes/proxy_backend.conf;' >> /etc/nginx/conf.d/default.conf && \
    echo '        index index.html index.htm;' >> /etc/nginx/conf.d/default.conf && \
    echo '        root /usr/share/nginx/html;' >> /etc/nginx/conf.d/default.conf && \
    echo '    }' >> /etc/nginx/conf.d/default.conf && \
    echo '    include includes/location_common.conf;' >> /etc/nginx/conf.d/default.conf && \
    echo '}' >> /etc/nginx/conf.d/default.conf
