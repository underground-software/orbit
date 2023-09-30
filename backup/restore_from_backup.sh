#!/bin/bash

PREFIX='/var/orbit'
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
TIMESTAMP=$(date +%s)

PS4="-|"
set -e -x

if [ -z "${1}" ]; then
	echo "error: backup archive filename argument required"
	exit 1
fi

preserve_grades_db=
while getopts "gh" opt; do
	case ${opt} in
		h)
			echo "use -g to preserve grades.db"
			;;
		g)
			preserve_grades_db=yes
			;;
		*)
			echo "unknown option"
			;;
	esac
done
shift $(($OPTIND - 1))

FILENAME=`basename $1`

die() { echo "error: $1" ; exit 1 ; }

echo "KDLP ORBIT RESTORE FROM BACKUP $FILENAME"

BACKUP="$PREFIX/backups/$FILENAME"
test -f $BACKUP || die "no such backup '$BACKUP'"

mkdir restore.$TIMESTAMP
cd restore.$TIMESTAMP
cp $BACKUP .
tar --xattrs --xattrs-include='*' -pxf $BACKUP
ls

if [ -z "$preserve_grades_db" ]; then
	echo "[1] Restore grades.db from $(ls grades*)"
	rm -rf $PREFIX/cano.py/mercury/grades.db
	cp --preserve=xattr -a grades.db* $PREFIX/cano.py/mercury/grades.db
else
	echo "[1] Option -g: Preserve grades.db"
fi

echo "[2] Restore users.db from $(ls users*)"
rm -rf $PREFIX/cano.py/venus/users.db
cp --preserve=xattr -a users.db* $PREFIX/cano.py/venus/users.db

echo "[3] Restore email_data from $(ls | grep email_data)"
rm -rf $PREFIX/email_data
cp --preserve=xattr -ar email_data*/email_data $PREFIX/
