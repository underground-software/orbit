#!/bin/sh -e
#
# the warp drive allows you to enter hyperspace

cd "$(dirname "$0")"

DOCKER=${DOCKER:-podman}
CONTAINER=${CONTAINER:-syzygy_orbit_1}

cat <<EOF | $DOCKER exec -i $CONTAINER /bin/sh
. /radius-venv/bin/activate
/orbit/hyperspace.py $@
EOF
