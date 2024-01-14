#!/bin/sh -e
cd "$(dirname "$0")"

FQDN="$(./config.py srvname)"
DOC_ROOT="$(./config.py doc_root)"
RADIUS_PORT="$(./config.py radius_port)"
SMTP_PORT="$(./config.py smtp_port)"
SMTP_PORT_EXT="$(./config.py smtp_port_ext)"
POP3_PORT="$(./config.py pop3_port)"
POP3_PORT_EXT="$(./config.py pop3_port_ext)"

# Make this script easy to run on a host machine without certbot
if ! hash certbot; then
	alias certbot=true
fi

SSL_RAW="$(certbot certificates -d "$FQDN")"
SSL_CRT="$(printf "$SSL_RAW" | awk -F': ' '/Certificate Path/ { print $2 }')"
SSL_KEY="$(printf "$SSL_RAW" | awk -F': ' '/Private Key Path/ { print $2 }')"

cat <<EOF
# orbit nginx configuration
# generated on $(date) by $(basename "$0")

user nginx;
worker_processes auto;
error_log /var/log/nginx/error.log notice;
pid /run/nginx.pid;

load_module /usr/lib/nginx/modules/ngx_mail_module.so;

events {
	worker_connections 1024;
}

http {
	log_format  main  '\$remote_addr - \$remote_user [\$time_local] "\$request" '
		      '\$status \$body_bytes_sent "\$http_referer" '
		      '"\$http_user_agent" "\$http_x_forwarded_for"';

	access_log  /var/log/nginx/access.log  main;

	sendfile            on;
	tcp_nopush          on;
	keepalive_timeout   65;
	types_hash_max_size 4096;

	include             /etc/nginx/mime.types;
	default_type        application/octet-stream;

	server {
		ssl_certificate /etc/letsencrypt/live/$FQDN/fullchain.pem;
		ssl_certificate_key /etc/letsencrypt/live/$FQDN/privkey.pem;
		server_name $FQDN;
		listen 443 ssl;
		listen [::]:443 ssl;
		include /etc/letsencrypt/options-ssl-nginx.conf;
		ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;
		error_page 401 /login?target=\$uri;
		error_page 403 /403.md;
		error_page 404 /404.md;
		error_page 502 /502.md;
		error_page 502 /502.md;
		error_page 500 /500.md;

		# DOCUMENT ROOT
		location / {
		    root $DOC_ROOT;
		}

		# MATRIX
		location /.well-known/matrix/client {
			return 200 '{"m.homeserver": {"base_url": "https://$FQDN:$MATRIX_PORT"}}';
			default_type application/json;
			add_header Access-Control-Allow-Origin *;
		}
		location = / {
		    rewrite .* /index.md;
		}

		# RADIUS
		location ~* ^((.*\.md)|/log(in|out)|/dashboard|/register|/mail_auth|/cgit.*)$ {
			include uwsgi_params;
			proxy_pass http://localhost:$RADIUS_PORT;
		}
	}
	server {
		listen 80;
		listen [::]:80;
		if (\$host = $FQDN) {
			return 301 https://\$host\$request_uri;
		}
		return 404;
	}
}

mail {
	proxy_pass_error_message on;

	ssl_certificate $SSL_CRT;
	ssl_certificate_key $SSL_KEY;
	ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;

	server {
		auth_http 127.0.0.1:$RADIUS_PORT/mail_auth;
		listen $SMTP_PORT_EXT ssl;
		protocol smtp;
		smtp_auth plain login;
		proxy_smtp_auth on;
		xclient off;
	}

	server {
		auth_http 127.0.0.1:$RADIUS_PORT/mail_auth;
		listen $POP3_PORT_EXT ssl;
		protocol pop3;
		pop3_auth plain;
	}
}
EOF
