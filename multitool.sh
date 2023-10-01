#!/bin/bash
#
# multitool.sh: multipurpose script to manage users
# and sessions of the auth.py backend
#
# features (added as they are developed):
# - change password for a user
# - list users
# - check whether a user exists
# - check whether a user has a valid session
# - delete a user
# - add user & pass
# - validate a user & pass pair
# - list sessions
# - logout a user from their current session 
# possible extensions:
# - make database references path generic
# - run from ExecutionConfig

usage() {
	echo "usage of $(basename $0):"
	echo "no argument: list active user sessions"
	echo " -s: check for valid user session"
	echo " -d: drop existing session for user"
	echo " -c: create session for user and get token"
	echo " -v: validate a username and password pair"
	echo " -n: create new user with supplied password"
	echo " -m: set new password of username to one supplied"
	echo " -w: delete (\"withdraw\") user from database"
	echo " -r: list all users (\"roster\")"
	echo " -i: increased information (more verbose output)"
	echo " -b: call bcrypt hash function on tool input"
	echo " -u <user>: specify a username to be used"
	echo " -p <pass>: specify a password to be used"
	echo " -t <token>: specify a session token to be used"

	exit 0
}

Echo() {
	if [ "${VERBOSE}" == "yes" ]; then
		echo -e $@
	fi
}

die() {
	echo -e "error: ${1}" > /dev/stderr
	exit 1
}

do_drop_session() {
	URI="${AUTH_SERVER}/logout?username=${USER}"
	HEADERS="Content-Type: application/x-www-form-urlencoded"
	echo "GET ${URI} HTTP/1.1"
	curl -H "${HEADERS}" -X GET "${URI}"
	echo
}

do_create_session() {
	URI="${AUTH_SERVER}/login"
	BODY="username=${USER}&password=${PASS}&quiet=yes"

	Echo "POST ${URI} body: [${BODY}] HTTP/1.1"
	curl -s -d "${BODY}" -X POST "${URI}" > token
	TOKEN="$(cat token)"
	
	if [ "${TOKEN}" == "null" ]; then
		die "unable to create session: check credentials"
	fi

	echo -e "${TOKEN}"
}

need_username_or_die() {
	test -z "${USER}" && die "no username supplied"
}

need_password_or_die() {
	test -z "${PASS}" && die "no password supplied"
}

need_token_or_die() {
	test -z "${TOKEN}" && die "no token supplied"
}


need_credentials_or_die() {
	need_username_or_die
	need_password_or_die
}

do_validate_credentials() {
	URI="${AUTH_SERVER}/check?username=${USER}"

	need_credentials_or_die

	CMD="SELECT pwdhash FROM users WHERE username = '${USER}';"
	Echo "Running sqlite command on $(basename "${DB}"): '${CMD}'"

	HASH=`sqlite3 "${DB}" "${CMD}"`

	Echo "Hash from $(basename "${DB}"): '${HASH}'"

	# if $HASH is empty,
	# then $USER does not exist
	# therefore jump to invalid caase
	if [ -z "${HASH}" ]; then
		echo "null"
		return 1
	fi

	VALID=$(cat <<EOF | python3
import bcrypt
if bcrypt.checkpw(b'${PASS}', b'${HASH}'):
	print("${USER}")
else:
	print("null")
EOF
	)

	echo "${VALID}"

	if [ "${VALID}" == "null" ]; then
		return 1
	fi
}

do_list_sessions() {
	CMD="SELECT token, username, expiry FROM sessions;"
	Echo "Running sqlite command on $(basename "${DB}") '${CMD}'"
	OUT=`sqlite3 "${DB}" "${CMD}"`
	echo -e "${OUT}"
}

do_hash_password() {
	need_password_or_die

	PWDHASH=$(cat <<EOF | python3
from bcrypt import hashpw, gensalt
print(str(hashpw(b"${PASS}", gensalt()), "UTF-8"))
EOF
	)

	if [ -z ${PWDHASH} ]; then
		die "unable invoke bcrypt hash function"
	fi

	echo "${PWDHASH}"
}

do_new_user() {
	need_credentials_or_die

	PWDHASH=$(do_hash_password)

	Echo "OK: hashpw(${PASS}, gensalt())=${PWDHASH}"

	CMD="INSERT INTO users (username, pwdhash, lfx) VALUES ('${USER}', '${PWDHASH}', false);"

	Echo "Running sqlite command on $(basename "${DB}") '${CMD}'"

	if sqlite3 "${DB}" "${CMD}" 2>& 1 | grep "UNIQUE constraint failed" > /dev/null; then
		die "username '${USER}' taken"
	fi

	# save and restore verbosity
	# since within this call we strictly want the main output
	PUSH_VERBOSE=${VERBOSE}
	VERBOSE='no'
	valid=$(do_validate_credentials)
	VERBOSE=${PUSH_VERBOSE}

	if [ "${valid}" != "${USER}" ]; then
		die "failed to add user ${USER}"
	else
		echo "credentials = { username: ${USER}, password: ${PASS} }"
	fi
}

# delete sam, sa, sa2, sa3 sa4 a5

do_delete_user() {
	need_username_or_die

	if ! do_existence_check_user > /dev/null; then
		echo "null"
		return 1
	fi

	CMD="DELETE FROM users WHERE username = '${USER}';"

	Echo "Running sqlite command on $(basename "${DB}") '${CMD}'"

	if ! sqlite3 "${DB}" "${CMD}"; then
		die "failed to delete user '${USER}'"
	fi

	echo "${USER}"
}

do_existence_check_user() {
	need_username_or_die

	CMD="SELECT pwdhash FROM users WHERE username = '${USER}';"
	PWDHASH=$(sqlite3 "${DB}" "${CMD}")

	# if we lookup a password in the database for $USER and find nothing
	# then the user does not exist
	if [ -z "${PWDHASH}" ]; then
		echo "null"
		return 1

	else
		echo "${USER}"
	fi

}

do_list_roster_users() {
	CMD="SELECT id, username, pwdhash, lfx FROM users;"
	Echo "Running sqlite command on $(basename "${DB}"): '${CMD}'"
	OUT=`sqlite3 "${DB}" "${CMD}"`
	echo -e "${OUT}"
	
}

do_mutate_pwdhash_user() {
	need_credentials_or_die


	if ! do_existence_check_user > /dev/null; then
		die "cannot change password of nonexistent user '${USER}'"
	fi

	PWDHASH=$(do_hash_password)

	CMD="UPDATE users SET pwdhash = '${PWDHASH}' WHERE username = '${USER}'"
	Echo "Running sqlite command on $(basename "${DB}"): '${CMD}'"
	sqlite3 "${DB}" "${CMD}"

	echo "credentials = { username: ${USER}, password: ${PASS} }"
}

do_make_lfx_user() {
	need_username_or_die


	if ! do_existence_check_user > /dev/null; then
		die "cannot change lfx status of nonexistent user '${USER}'"
	fi

	PWDHASH=$(do_hash_password)

	CMD="UPDATE users SET lfx = TRUE WHERE username = '${USER}'"
	Echo "Running sqlite command on $(basename "${DB}"): '${CMD}'"
	sqlite3 "${DB}" "${CMD}"

	echo "credentials = { username: ${USER}, lfx: true }"
}

do_check_session() {
	need_token_or_die

	URI="${AUTH_SERVER}/check?token=${TOKEN}"
	HEADERS="Content-Type: application/x-www-form-urlencoded"
	echo "GET ${URI} HTTP/1.1"
	curl -H "${HEADERS}" -X GET "${URI}"
	echo
}

# from: https://stackoverflow.com/questions/59895/how-do-i-get-the-directory-where-a-bash-script-is-located-from-within-the-script
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

# configuration defaults
USER=
PASS=
TOKEN=
# default naked invocation to list all known sessions
OP="list_sessions"
# all one thing, testing TODO
AUTH_SERVER=${ALT_AUTH_SERVER:-localhost:9098}
VERBOSE='no'

while getopts "f:sminawehdblcvru:p:t:" X; do
	case ${X} in
		i)
			VERBOSE='yes'
			;;
		s)
			OP="check_session"
			;;
		b)
			OP="hash_password"
			;;
		n)
			OP="new_user"
			;;
		w)
			OP="delete_user"
			;;
		e)
			OP="existence_check_user"
			;;
		d)
			OP="drop_session"
			;;
		c)
			OP="create_session"
			;;
		v)
			OP="validate_credentials"
			;;
		r)
			OP="list_roster_users"
			;;
		m)
			OP="mutate_pwdhash_user"
			;;
		l)
			OP="make_lfx_user"
			;;
		u)
			USER=${OPTARG}
			;;
		p)
			PASS=${OPTARG}
			;;
		t)
			TOKEN=${OPTARG}
			;;
		h)
			usage
			;;
		*)
			usage
			;;
	esac
done
shift $(($OPTIND - 1))

# We need to make sure all database calls are local to this repo
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

DB="${SCRIPT_DIR}/${ALT_DB:-orbit.db}"


Echo "ExecutionConfig = {"
Echo "\toperation: '${OP}'"
Echo "\tusername: '${USER}'"
Echo "\tpassword: '${PASS}'"
Echo "\ttoken: '${TOKEN}'"
Echo "\tdb: '${DB}'"
Echo "}"

do_${OP}
