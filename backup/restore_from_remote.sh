#!/bin/bash

export SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
REMOTE=${PROD_REMOTE:-$(cat ${SCRIPT_DIR}/prod.hostname)}
TIMESTAMP=${1:-$(date +%s)}

PS4="-|"
set -e -x

$SCRIPT_DIR/do_remote_backup.sh "$TIMESTAMP"
$SCRIPT_DIR/restore_from_backup.sh "${SCRIPT_DIR}/kdlp-$REMOTE-backup.$TIMESTAMP.tar.gz"
