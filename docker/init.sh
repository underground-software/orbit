#!/bin/sh -e
cd "$(dirname "$0")"

# Download the latest website data. Do this in init.sh so it's not necessary to
# rebuild the docker image when the website is updated.
DATAROOT="$(../config.py dataroot)"
DOCSRC="$(../config.py docsrc)"
if [ ! -e "$DATAROOT" ]; then
  git clone "$DOCSRC" "$DATAROOT"
  git -C "$DATAROOT" checkout master
else
  git -C "$DATAROOT" pull
fi

# Run the services
s6-svscan ./s6-services
