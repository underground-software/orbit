import sqlite3
import config
# nickname  table name
# USR => users
# ASN => assignments
# SUB => submissions
# REG => newusers
import sys

def _do(cmd, reps, set_=False, get_=False):
    if config.sql_verbose:
        print("SQL", cmd, file=sys.stderr)
    dat = None
    con = sqlite3.connect(config.database)
    new = con.cursor()
    ret = new.execute(cmd, reps)
    if get_:
        dat = ret.fetchall()
        if len(dat) < 1:
            dat = [None]
        if config.sql_verbose:
            print("SQLRET", dat, file=sys.stderr)
        # works when get lookup fails
    if set_:
        ret.execute("COMMIT;")
    con.close()
    return dat

_set = lambda cmd, reps: _do(cmd, reps, set_=True, get_=True)
_get = lambda cmd, reps: _do(cmd, reps, get_=True)

# session table interface

SES_GETBY_TOKEN="""
SELECT token, username, expiry
FROM sessions
WHERE token = ?;
""".strip()
ses_getby_token         = lambda tok: _get(SES_GETBY_TOKEN, (tok,))

SES_SETEXPIRY_TOKEN="""
UPDATE sessions
SET expiry = ?
WHERE token = ?;
""".strip()
ses_setexpiry_token     = lambda tex: _set(SES_SETEXPIRY_TOKEN, tex)

SES_GETBY_USERNAME="""
SELECT token, username, expiry
FROM sessions
WHERE username = ?;
""".strip()
ses_getby_username      = lambda usn: _get(SES_GETBY_USERNAME, (usn,))

SES_INS="""
INSERT INTO sessions (token, username, expiry)
VALUES (?, ?, ?)
RETURNING username;
""".strip()
ses_ins                 = lambda tpl: _set(SES_INS, tpl)

SES_DELBY_TOKEN="""
DELETE FROM sessions
WHERE token = ?
RETURNING username;
""".strip()
ses_delby_token         = lambda tok: _set(SES_DELBY_TOKEN, (tok,))

SES_DELBY_USERNAME= """
DELETE FROM sessions
WHERE username = ?
RETURNING username;
""".strip()
ses_delby_username      = lambda usn: _set(SES_DELBY_USERNAME, (usn,))

SES_GET="""
SELECT token, username, expiry
FROM sessions;
""".strip()
ses_get                 = lambda    : _get(SES_GET, ())

# users table interface

USR_PWDHASHFOR_USERNAME="""
SELECT pwdhash
FROM users
WHERE username = ?;
""".strip()
usr_pwdhashfor_username = lambda usn: _get(USR_PWDHASHFOR_USERNAME, (usn,))

USR_INS="""
INSERT INTO users (username, pwdhash, lfx, student_id)
VALUES (?, ?, ?, ?);
""".strip()
usr_ins                 = lambda usr: _set(USR_INS, usr)

USR_DELBY_USERNAME="""
DELETE FROM users
WHERE username = ?
RETURNING username;
""".strip()
usr_delby_username      = lambda usn: _set(USR_DELBY_USERNAME, (usn,))

USR_SETPWDHASH_USERNAME="""
UPDATE users
SET pwdhash = ?
WHERE username = ?;
""".strip()
usr_setpwdhash_username = lambda usr: _set(USR_SETPWDHASH_USERNAME, usr)

USR_GET="""
SELECT id, username, pwdhash, lfx, student_id
FROM users;
""".strip()
usr_get                 = lambda    : _get(USR_GET, ())

USR_GETBY_USERNAME="""
SELECT id, username, pwdhash, lfx, student_id
FROM users
WHERE username = ?;
""".strip()
usr_getby_username      = lambda usn: _get(USR_GETBY_USERNAME, (usn,))


USR_SET_LFX="""
UPDATE users
SET lfx = True
WHERE username = ?;
""".strip()
usr_set_lfx             = lambda usn: _set(USR_SET_LFX, (usn,))

USR_SET_NOLFX="""
UPDATE users
SET lfx = False
WHERE username = ?;
""".strip()
usr_set_nolfx           = lambda usn: _set(USR_SET_NOLFX, (usn,))

USR_GETIF_LFX_USERNAME="""
SELECT lfx
FROM users
WHERE username = ?;
""".strip()
usr_getif_lfx_username  = lambda usn: _get(USR_GETIF_LFX_USERNAME, (usn,))

# submission table interface

SUB_GETFOR_USERNAME_ASN="""
SELECT (submission_id, student_id, assignment_id,
    submission_name, submission_grade, submission_comments)
FROM submissions
WHERE student_id = ?
AND assignment_id = ?;
""".strip()
sub_getfor_username_asn = lambda dub: _get(SUB_GETFOR_USERNAMEASN, p)

SUBS_GET="""
SELECT *
FROM submissions;
""".strip()
sub_get                 = lambda    : _get(SUB_GET, ())

SUB_INS="""
INSERT INTO submissions (sub_id, username, timestamp, _from, _to, email_ids, subjects)
VALUES (?,?,?,?,?,?,?);
""".strip()
sub_ins                 = lambda sub: _set(SUB_INS, sub)

SUB_GETBY_SUBID="""
SELECT sub_id, username, timestamp, _from, _to, email_ids, subjects
FROM submissions
WHERE sub_id = ?;
""".strip()
sub_getby_subid         = lambda sid: _get(SUB_GETBY_SUBID, (sid))

SUB_GETBY_USERNAME="""
SELECT sub_id, username, timestamp, _from, _to, email_ids, subjects
FROM submissions
WHERE user = ?;
""".strip()
sub_getby_username      = lambda usr: _get(SUB_GETBY_USERNAME, (usr))

# assignment table interface

ASN_GETBY_WEBID="""
SELECT web_id, email_id
FROM assignments
WHERE web_id = ?;
""".strip()
asn_getby_webid         = lambda wid: _get(ASN_GETBY_WEBID, (web_id))

ASN_GETBY_EMAILID="""
SELECT web_id, email_id
FROM assignments
WHERE email_id = ?;
""".strip()
asn_getby_email_id      = lambda eid: _get(ASN_GETBY_EMAIL_ID, (eid))

ASN_GET="""
SELECT *
FROM assignments;
""".strip()
asn_get                 = lambda    : _get(ASN_GET, ())

# registration table inferface

REG_INS="""
INSERT VALUES username, password, student_id = (?,?,?)
INTO accounts;
""".strip()
reg_ins                 = lambda tpl: _set(REG_INS, (tpl))

REG_GETBY_STUID="""
SELECT registration_id, username, password
FROM newusers
WHERE student_id = ?;
""".strip()
reg_getby_stuid         = lambda sid: _set(REG_GETBY_STUDENTID, (sid))

REG_DELBY_REGID="""
DELETE FROM accounts
WHERE id = ?;
""".strip()
reg_delby_regid         = lambda rid: _get(REG_DEL_BY_REGISRATION_ID, (rid))
