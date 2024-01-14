#!/bin/sh -e
cd "$(dirname "$0")"

# Run the services
s6-svscan ./s6-services
