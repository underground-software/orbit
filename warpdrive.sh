#!/bin/sh -e
#
# the warp drive allows you to enter hyperspace

cd "$(dirname "$0")"

DOCKER=${DOCKER:-sudo docker}

cat <<EOF | $DOCKER exec -i docker_orbit_1 /bin/sh
. /radius-venv/bin/activate
/orbit/hyperspace.py $@
EOF
