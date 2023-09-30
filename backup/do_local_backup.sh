#!/bin/bash

PREFIX='/var/orbit'
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
TIMESTAMP=${1:-$(date +%s)}

echo "KDLP ORBIT LOCAL DATA BACKUP SCRIPT @ $TIMESTAMP"

echo "[1]: back up users.db from venus"

cp --preserve=xattr -a $PREFIX/cano.py/venus/users.db $SCRIPT_DIR/users.db.$TIMESTAMP

echo "[2]: back up grades.db from mercury"

cp --preserve=xattr -a $PREFIX/cano.py/mercury/grades.db $SCRIPT_DIR/grades.db.$TIMESTAMP

echo "[3]: back up email_data"

DEST=$PREFIX/backups/email_data.$TIMESTAMP
mkdir -p $DEST
cp --preserve=xattr -ar $PREFIX/email_data $DEST

echo "[4]: output archive kdlp-prod-backup.$TIMESTAMP.tar.gz"
cd $SCRIPT_DIR
tar --xattrs --xattrs-include='*' -pcf kdlp-prod-backup.$TIMESTAMP.tar.gz users.db.$TIMESTAMP grades.db.$TIMESTAMP email_data.$TIMESTAMP
