#!/bin/sh -ex
cd "$(dirname "$0")"

# Test web server
curl --insecure "https://127.0.0.1"

# Test pop3
POP3_PORT="$(./config.py pop3_port)"
printf "QUIT\r\n"           | \
  nc localhost "$POP3_PORT" | \
	diff -up - <(printf "220 SMTP server ready\r\n221 Goodbye\r\n")


# Test smtp
SMTP_PORT="$(./config.py smtp_port)"
printf "QUIT\r\n"           | \
  nc localhost "$SMTP_PORT" | \
	diff -up - <(printf "220 SMTP server ready\r\n221 Goodbye\r\n")
