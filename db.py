import sqlite3
import config
# nickname  table name
# USR => users
# ASN => assignments
# SUB => submissions
# REG => newusers
import sys


def _do(cmd, reps=(), set_=False, get_=False):
    if config.sql_verbose:
        print("SQL", cmd, file=sys.stderr)
    reps = (lambda x: x if type(x) is tuple else (x,))(reps)
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


def _set(cmd, reps=()): return _do(cmd, reps, set_=True, get_=True)
def _get(cmd, reps=()): return _do(cmd, reps, get_=True)


# session table interface

SES_GETBY_TOKEN = """
SELECT token, username, expiry
FROM sessions
WHERE token = ?;
""".strip()
def ses_getby_token(tok): return _get(SES_GETBY_TOKEN, tok)


SES_SETEXPIRY_TOKEN = """
UPDATE sessions
SET expiry = ?
WHERE token = ?;
""".strip()
def ses_setexpiry_token(tex): return _set(SES_SETEXPIRY_TOKEN, tex)


SES_GETBY_USERNAME = """
SELECT token, username, expiry
FROM sessions
WHERE username = ?;
""".strip()
def ses_getby_username(usn): return _get(SES_GETBY_USERNAME, usn)


SES_INS = """
INSERT INTO sessions (token, username, expiry)
VALUES (?, ?, ?)
RETURNING username;
""".strip()
def ses_ins(tpl): return _set(SES_INS, tpl)


SES_DELBY_TOKEN = """
DELETE FROM sessions
WHERE token = ?
RETURNING username;
""".strip()
def ses_delby_token(tok): return _set(SES_DELBY_TOKEN, tok)


SES_DELBY_USERNAME = """
DELETE FROM sessions
WHERE username = ?
RETURNING username;
""".strip()
def ses_delby_username(usn): return _set(SES_DELBY_USERNAME, usn)


SES_GET = """
SELECT token, username, expiry
FROM sessions;
""".strip()
def ses_get(): return _get(SES_GET)


# users table interface

USR_PWDHASHFOR_USERNAME = """
SELECT pwdhash
FROM users
WHERE username = ?;
""".strip()
def usr_pwdhashfor_username(usn): return _get(USR_PWDHASHFOR_USERNAME, usn)


USR_INS = """
INSERT INTO users (username, pwdhash, lfx, student_id)
VALUES (?, ?, ?, ?);
""".strip()
def usr_ins(usr): return _set(USR_INS, usr)


USR_DELBY_USERNAME = """
DELETE FROM users
WHERE username = ?
RETURNING username;
""".strip()
def usr_delby_username(usn): return _set(USR_DELBY_USERNAME, usn)


USR_SETPWDHASH_USERNAME = """
UPDATE users
SET pwdhash = ?
WHERE username = ?;
""".strip()
def usr_setpwdhash_username(usr): return _set(USR_SETPWDHASH_USERNAME, usr)


USR_GET = """
SELECT id, username, pwdhash, lfx, student_id
FROM users;
""".strip()
def usr_get(): return _get(USR_GET)


USR_GETBY_USERNAME = """
SELECT id, username, pwdhash, lfx, student_id
FROM users
WHERE username = ?;
""".strip()
def usr_getby_username(usn): return _get(USR_GETBY_USERNAME, usn)


USR_SET_LFX = """
UPDATE users
SET lfx = True
WHERE username = ?;
""".strip()
def usr_set_lfx(usn): return _set(USR_SET_LFX, usn)


USR_SET_NOLFX = """
UPDATE users
SET lfx = False
WHERE username = ?;
""".strip()
def usr_set_nolfx(usn): return _set(USR_SET_NOLFX, usn)


USR_GETIF_LFX_USERNAME = """
SELECT lfx
FROM users
WHERE username = ?;
""".strip()
def usr_getif_lfx_username(usn): return _get(USR_GETIF_LFX_USERNAME, usn)


# submission table interface

SUB_GETFOR_USERNAME_ASN = """
SELECT (submission_id, student_id, assignment_id,
    submission_name, submission_grade, submission_comments)
FROM submissions
WHERE student_id = ?
AND assignment_id = ?;
""".strip()
def sub_getfor_username_asn(dub): return _get(SUB_GETFOR_USERNAME_ASN, dub)


SUB_GET = """
SELECT *
FROM submissions;
""".strip()
def sub_get(): return _get(SUB_GET)


SUB_INS = """
INSERT INTO submissions (sub_id, username, timestamp, _from, _to, email_ids, subjects)
VALUES (?,?,?,?,?,?,?);
""".strip()  # NOQA: E501
def sub_ins(sub): return _set(SUB_INS, sub)


SUB_GETBY_SUBID = """
SELECT sub_id, username, timestamp, _from, _to, email_ids, subjects
FROM submissions
WHERE sub_id = ?;
""".strip()
def sub_getby_subid(sid): return _get(SUB_GETBY_SUBID, sid)


SUB_GETBY_USERNAME = """
SELECT sub_id, username, timestamp, _from, _to, email_ids, subjects
FROM submissions
WHERE user = ?;
""".strip()
def sub_getby_username(usr): return _get(SUB_GETBY_USERNAME, usr)


# assignment table interface

ASN_GETBY_WID = """
SELECT web_id, email_id
FROM assignments
WHERE web_id = ?;
""".strip()
def asn_getby_webid(wid): return _get(ASN_GETBY_WID, wid)


ASN_GETBY_EID = """
SELECT web_id, email_id
FROM assignments
WHERE email_id = ?;
""".strip()
def asn_getby_email_id(eid): return _get(ASN_GETBY_EID, eid)


ASN_GET = """
SELECT *
FROM assignments;
""".strip()
def asn_get(): return _get(ASN_GET)


# registration table inferface

REG_INS = """
INSERT INTO newusers (username, password, student_id)
VALUES (?,?,?);
""".strip()
def reg_ins(tpl): return _set(REG_INS, tpl)


REG_GETBY_STUID = """
SELECT registration_id, username, password
FROM newusers
WHERE student_id = ?;
""".strip()
def reg_getby_stuid(sid): return _set(REG_GETBY_STUID, sid)


REG_DELBY_REGID = """
DELETE FROM newusers
WHERE registration_id = ?;
""".strip()
def reg_delby_regid(rid): return _get(REG_DELBY_REGID, rid)
