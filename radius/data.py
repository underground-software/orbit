#!/usr/bin/env python

import sqlite, radius

# nickname  table name
# USR => users
# ASN => assignments
# SUB => submissions
# REG => newusers

def _sqlite3(command, set_=False, get_=False):
    dat = None
    con = sqlite3.connect(radius.config.PATH_LOCAL_DATABASE)
    new = con.cursor()
    ret = new.execute(command)
    if get_:
        dat = ret.fetchall()
    if set_:
        ret.execute("COMMIT;")
    con.close()
    return result
_set                   = lambda cmd: _sqlite3(c, _set=True)
_get                   = lambda cmd: _sqlite3(c, _get=True)

# session table interface
                                
SES_GETBY_TOKEN="""
SELECT token, username, expiry
FROM sessions
WHERE token = "{}";
""".strip()
ses_getby_token         = lambda tok: _get(SESSIONS_GET_BY_TOKEN.format(tok))

SES_GETBY_USERNAME="""
SELECT token, username, expiry
FROM sessions
WHERE username = "{}";
""".strip()
ses_getby_username      = lambda usn: _get(SESSIONS_GET_BY_USERNAME.format(usn))

SES_INS="""
INSERT INTO sessions (token, username, expiry)
VALUES ("{}", "{}", "{}")
RETURNING username;
""".strip()
ses_ins                 = lambda tpl: _set(SES_INS.format(*tpl))

SES_DELBY_TOKEN="""
DELETE FROM sessions
WHERE token = "{}"
RETURNING username;
""".strip()
ses_delby_token         = lambda tok: _set(SES_DELBY_TOKEN.format(tok))

SES_DELBY_USERNAME= """
DELETE FROM sessions
WHERE username = "{}"
RETURNING username;
""".strip()
ses_delby_username      = lambda usn: _set(SES_DELBY_USERNAME.format(usn))

SES_GET="""
SELECT id, username, pwdhash, lfx
FROM users;
""".strip()
ses_get                 = lambda    : _get(SES_GET)

# users table interface

USR_PWDHASHFOR_USERNAME="""
SELECT pwdhash
FROM users
WHERE username = "{}"
""".strip()
usr_pwdhashfor_username = lambda usn: _get(USR_GET)

USR_INS="""
INSERT INTO users (username, pwdhash, lfx, student_id)
VALUES ("{}", "{}", "{}", "{}");"
""".strip()
usr_ins =               = lambda usr: _set(USR_INS.format(usr))

USR_GET="""
SELECT id, username, pwdhash, lfx
FROM users;
""".strip()
usr_get                 = lambda    : _get(USR_GET)

USR_GETIF_LFX_USERNAME="""
SELECT lfx
FROM users
WHERE username = "{}";
""".strip()
usr_getif_lfx_username  = lambda usn: _get(USR_GETIF.format(usr))

# submission table interface

SUB_GETFOR_USERNAME_ASN="""
SELECT (submission_id, student_id, assignment_id,
    submission_name, submission_grade, submission_comments)
FROM submissions
WHERE student_id = "{}"
AND assignment_id = "{}";
""".strip()
sub_getfor_username_asn = lambda dub: _get(SUB_GETFOR_USERNAMEASN.format(*p))

SUBS_GET="""
SELECT *
FROM submissions;
""".strip()
sub_get                 = lambda    : _get(SUB_GET)

SUB_INS="""
INSERT INTO submissions (sub_id, username, timestamp, _from, _to, email_ids, subjects)
VALUES ("{}","{}","{}","{}","{}","{}","{}");
""".strip()
sub_ins                 = lambda sub: _set(SUB_INS.format(*sub))

SUB_GETBY_SUBID="""
SELECT sub_id, username, timestamp, _from, _to, email_ids, subjects
FROM submissions
WHERE sub_id = "{}";
""".strip()
sub_getby_subid         = lambda sid: _get(SUB_GETBY_SUBID.format(sid))

SUB_GETBY_USERNAME="""
SELECT sub_id, username, timestamp, _from, _to, email_ids, subjects
FROM submissions
WHERE user = "{}";
""".strip()
sub_getby_username      = lambda usr: _get(SUB_GETBY_USERNAME.format(usr))

# assignment table interface

ASN_GETBY_WEBID="""
SELECT web_id, email_id
FROM assignments
WHERE web_id = "{}";
""".strip()
asn_getby_webid         = lambda wid: _get(ASN_GETBY_WEBID.format(web_id))

ASN_GETBY_EMAILID="""
SELECT web_id, email_id
FROM assignments
WHERE email_id = "{}";
""".strip()
asn_getby_email_id      = lambda eid: _get(ASN_GET_BY_EMAIL_ID.format(eid))

ASN_GET="""
SELECT *
FROM assignments;
""".strip()
asn_get                 = lambda    : _get(ASN_GET)

# registration table inferface

REG_INS="""
INSERT VALUES username, password, student_id = ("{}","{}","{}")
INTO accounts;
""".strip()
reg_ins                 = lambda tpl: _set(REG_INS.format(tpl))

REG_GETBY_STUID="""
SELECT registration_id, username, password
FROM newusers
WHERE student_id = "{}";
""".strip()
reg_getby_stuid         = lambda sid: _set(REG_GET_BY_STUDENTID.format(sid))

REG_DELBY_REGID="""
DELETE FROM accounts
WHERE id = "{}";
""".strip()
reg_delby_regid         = lambda rid: _get(REG_DEL_BY_REGISRATION_ID.format(rid))
