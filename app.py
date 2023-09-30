#!/bin/env python3
#
# it's all one things now

from http import HTTPStatus
import markdown, os, re
import sys, datetime, bcrypt, hashlib
from datetime import datetime
import sqlite3

# nickname  table name
# USR => users
# ASN => assignments
# SUB => submissions
# REG => newusers

def cmd(cmd, set_=False, get_=False):
    dat = None
    # FIXME
    con = sqlite3.connect('/var/orbit/orbit.db')
    new = con.cursor()
    ret = new.execute(cmd)
    if get_:
        dat = ret.fetchall()
    if set_:
        ret.execute("COMMIT;")
    con.close()
    return dat

_set = lambda cmd: _sqlite3(c, _set=True)
_get = lambda cmd: _sqlite3(c, _get=True)

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
WHERE username = "{}";
""".strip()
usr_pwdhashfor_username = lambda usn: _get(USR_PWDHASHFOR_USERNAME.format(usn))

USR_INS="""
INSERT INTO users (username, pwdhash, lfx, student_id)
VALUES ("{}", "{}", "{}", "{}");
""".strip()
usr_ins                 = lambda usr: _set(USR_INS.format(usr))

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


def h(v, c, cls='', attrs=''):
    return f'<h{v} class="{cls}" {attrs} >{c}</h{v}>'

def t_i(i):
    return ''.join(['\t' for x in range(i)])

def o(i, c):
    return f'{t_i(i)}{c}\n'

def ooo(i, c, d, e, j=0):
    return f'{o(i, c)}{o(i+j, d)}{o(i, e)}'

def oOo(i, c, d, e):
    return ooo(i, c, d, e, j=1)

def oxo(i, c, d, e):
    return f'{o(i, c)}{d}{o(i, e)}'

def table_data(c, h=False, i=0):
    d = 'd'
    if h:
        d = 'h'
    a, b = f'<t{d}>', f'</t{d}>'
    return oOo(i, a, c, b)

def table_row(c, h=False, i=0):
    d = ''.join([table_data(d, h=h, i=i+1) for d in c])
    return oxo(i, '<tr>', d, '</tr>')

def table(c, i=0):
    t=''
    h=True
    for r in c:
        t += table_row(r, h, i=i+1)
        h=False
    return oxo(i, '<table>', t, '</table>')

def img(src, alt='', cls='', attrs=''):
    return f'<img src="{src}" alt="{alt}" class="{cls}" {attrs} />'

def div(cls, attr="", c="", i=0):
    return oxo(i, f'<div class="{cls}" {attr} >', c, '</div>')

def code(attr="", c="", i=0):
    return oxo(i, f'<code{attr}>', c, '</code>')

def li(c):
    return o(c)

def ul(c, i=0):
    return oxo(i, f'<ul>', '\n'.join([li(_li) for _li in c]), '</ul>')

def a(text, href, attrs=''):
    return f'<a {attrs} hrref="{href}">{text}</a>'

def nav_button(href, text):
    return a(href, text, attrs=' class="nav" ')

def button(c, i=0, a=''):
    return oOo(i, f'<button {a}>', c, '</button>')

def input_(attr=''):
    return f'<input {attr} >'

def DEBUG(strg):
    print(strg, file=sys.stderr)

def label(attr='', c=''):
    return f'<label {attr} >{c}</label>'

_pair_fmtr = lambda fmt: (lambda pr: fmt.format(pr[0], pr[1]))
_pair_join= lambda pair_list: '<br />'.join(pair_list)


_sepr_call = lambda x, y, z: z + x(y) + z
_pair_fmtr = lambda pair_list: pair_join([pair_fmtr(fmt)(pr) for pr in pair_list])

msg_blk = lambda pair_list: _sepr_call(_par, pair_list, sep)

encode  = lambda dat: bytes(dat, "UTF-8")
decode  = lambda dat: str(dat, "UTF-8")

# Constants
sec_per_min = 60
min_per_ses = 180

# === auth cookie implementation === 

# Under the assumption of the impossibility of two invocations of this function
# with equivalent values calclated from the 'username + str(datetime.now())' expression,
# this function guarantees unique session tokens for every successful login by $userame
_gen_hsh_inp = lambda username: (username + str(datetime.now()))
_gen_tok_hsh = lambda username: hashlib.sha256(_gen_hsh_inp(username)).hexdigest()

# Generate the expiration datetime pair from the value loaded from orbcfguration
# The first elenent is the dateime processed through a stanard formatstring
# The second element is number of seconds until the expiration datetime
_fmt_cok_tme = '%a, %d %b %Y %H:%M:%S GMT'
_gen_exp_now = lambda: datetime.utcnow() + datetime.timedelta(minutes=min_per_ses)
_gen_cok_tme = lambda: (gen_exp_now().strftime(fmt_cok_tme), sec_per_min * min_per_ses)

# Generate the information we need to set a user cookie for entire website on this domain.
# With a supplied session token set as the value, generate a semicolon-separated list
# of key=value pairs that will be remembered by the user
# The value of path could be adjusted to restrict the set of pages the user's web client
# to a subdomain of the server root.
_fmt_cok_val = 'auth={}; Expires={}; Max-Age={}; Path=/'
_gen_cok_val = lambda cok_val : fmt_cok_val.format(value, *gen_cok_tme())
_gen_cok_hdr = lambda cok_dat : [('Set-Cookie', gen_cok_val(cok_dat))]

_lod_cok_usr = lambda cok_usr: cok_usr.get('auth', None)
_lod_cok_tok = lambda cok_raw: _loq_cok_usr(http.cookies.BaseCookie('').load(cok_raw))

# Expose these entry points as the auth_cookie API
parse_cookie = _lod_cok_usr
parse_cookie.__doc__="""
    auth.cookie_parse: attempt to parse an auth cookie from raw data
    [args]
        raw : string
        |   attempt to parse this string formatted cookie data
    [return]
        | token hash value if a cookie was parsed successfully
        | None otherwise
    """.strip()

hdfor_cookie= _gen_cok_hdr
hdfor_cookie.__doc__="""
    auth.hdfor_cookie: generate the date set auth cookie via header
    [args]
        token : string
        |   valid session token to use as auth value
    [return]
        | token hash if a cookie was parsed successfully
        | None otherwise
    """.strip()

# === user sessionimplementation === 

class Session:
    """
    auth.Session: User session data

    ...

    Attributes
    ----------
    
    username : string
        A valid username for user session or '' if unauthenticated

    token : string
        A valid token for user session or '' if unauthenticated

    expiry : datetime.datetime
        Current session's expiration as datetime or None if unauthenticated

    remaining_validity : datetime.timedelta
        Time left until session expiry

    Methods
    -------

    expired()
        Get truth of whether this $self.expiry is in the past

    expiry_fmt()
        Get a printable, formatted string of $self.expiry

    """
    def __init__(self, token=None, username=None, expiry=None):
        self.token = token
        self.username = username
        self._expiry = None
        if expiry is not None:
            self._expiry = datetime.fromtimestamp(expiry)

    def expired(self):
        if expiry := self.expiry is None or datetime.utcnow().timestamp() > expiry:
            del_by_token(self.token)
            return True
        else:
            return False

    def expiry_fmt(self):
        return self._expiry.strftime('%a, %d %b %Y %H:%M:%S GMT')

    @property
    def expiry(self):
        return self._expiry.timestamp()

    @property
    def remaining_validity(self):
         return str(self._expiry - datetime.utcnow())

    def __repr__(self, tab='', nl='', end=''):
        return ( f'{tab}SES:{nl}'
                 f'{tab}USR:{tab}{self._msg}{nl}'
                 f'{tab}TOK:{tab}{self._queries}{nl}'
                 f'{tab}EXP:{tab}{self._path_info}{nl}'
                 f'{tab}){end}')

    def __str__(self):
        return repr(self, tab='\t', nl='\n\t', end='\n')

# === user session API === 

def new_by_username(username):
    """
    auth.new_by_username: create a new valid session for $username
        username : str
        |   assume $username is authentiated by caller and from this value construct a new session
    [return]
        | A valid session token for $username if session creation is successfull
        | None otherwise
    """
    if (session := get_by_username(username)):
        # This should never happen if get, del working
        if del_by_username(session.token) != 'username':
            [][0] # Generate an exception
            
    return data.usr_ins((get_tok_hsh(username), username), gen_expiry().timestamp())

def del_by_username(username):
    """
    auth.del_by_username: delete any extant valid session data for $username
        username : str
        |   lookup session for $username
    [return]
        | $token if this invocation sucessfully invalidates a corresponding valid session
        | None otherwise
    """
    return data.ses_delby_username(username)

def del_by_token(token):
    """
    auth.del_by_token: delete any extant valid session data for $token
        token  : str
        |   lookup session for $token
    [return]
        | $token if this invocation sucessfully invalidates a corresponding valid session
        | None otherwise
    """
    return data.ses_delby_token(token)

def get_by_username(username):
    """
    auth.get_by_username: get any extant valid session data for $username
        username : str
        |   lookup any sesion for $username
    [return]
        | session validated by $username if extant
        | None otherwise
    """
    return data.ses_getby_username(username)

def get_by_token(token):
    """
    auth.get_by_token: get any extant valid session data for $token
    [args]
        token : str
        |   lookup any sesion $token
    [return]
        | session validated by $token if extant
        | None otherwise
    """
    return data.ses_getby_token(token)

# Password hashing and checking handled by the bcrypt library
_chck_pass = lambda creds: bcrypt.checkpw(*tuple(map(orbit.bytes8, creds)))
_seek_hash = lambda creds: orbdbs.users_get_pwdhash_by_username(credentials[1])
enticate   = lambda creds: _chck_pass(creds[1], _seek_hash(creds[0]))
enticate.__doc__="""
    auth.enticate: attempt authentication
    [args]
        creds : list or tuple of str where len(creds) == 2
        |   attempt to parse this string formatted cookie data
    [return]
        |   True if successful
        |   False otherwise
    """.strip()

class Rocket:
    """
    radius.Rocket: Radius user request context
                   resposible for ensuring authention is performed correctly

    ...

    Attributes
    ----------
    root : str
        Absolute filesystem path to public data root

    path_info : str
        Absolute path requested by user

    queries : dict
        Dictionary of parsed URL queries (passsed by '?key1=value1&key2=value2' suffix)

    session : auth.Session
        The current valid session token if it exists or None

    username : string
        The valid current session username or '' if unauthenticated

    token : string
        The valid current session token or '' if unauthenticated

    expiry : datetime.datetime
        The current session's expiration time and date or None if unauthenticated

    remaining_validity : dattime.timedelta
         Time remaining remaining until session expiry
         return str(self._expiry - datetime.datetime.utcnow())

    Methods
    -------

    expiry_fmt()
        returns a printable and nicely formatted expiry date and time string

    env_get(self, key):
        try to get

    """

    def __init__(self, environ, start_res, cfg):
        self.root       = cfg.dataroot
        self._environ   = environ
        self._start_res = start_res
        self._path_info = None
        self._queires   = None
        self._session   = None
        self._from_user = None
        self._msg       = "(silence)"
        self._db        = cfg.database
        self._headers   = []
        self._format    = lambda x: x
        # Eventually, toggle CGI or WSGI
        self._raw_body  = lambda self: parse_qs(self.env_get('wsgi.input').read())


    def __repr__(self, tab='', nl='', end=''):
        return ( f'ROCK ({nl}'
                 f'COOK:{tab}{self._user_token}{nl}'
                 f'SESH:{tab}{str(self._session)}{nl}'
                 f'METH:{tab}{self._method_str()}{nl}'
                 f'HEAD:{tab}{self.headers}{nl}'
                 f'MESG:{tab}{self._msg}{nl}'
                 f'QURY:{tab}{self._queries}{nl}'
                 f'PATH:{tab}{self._path_info}{nl}'
                 f'){end}')

    def __str__(self):
        return repr(self, tab='\t', nl='\n\t', end='\n')

    def env_get(self, key):
        return self._environ.get(key, '')

    def msg(self, msg):
        self._msg = msg

    # this handles our two sesion case,
    # but this is the place to extend for more general multi-session usage
    def forwho(self):
        if self.session:
            return ['UML', 'LFX'][data.usr_getif_lfx_username(username) is not None]

    @property
    def method(self):
        return ['GET', 'POST'][int(self.environ.get('CONTENT_LENGTH', 0)) > 0]

    @property
    def path_info(self):
        if self._path_info is None:
            self._path_info = self.env_get("PATH_INFO")
        return self._path_info

    @property
    def queries(self):
        if self._queries is None:
            self._queries = self.env_get("QUERY_STRING")
        return self._queries

    def _token_from_cookie(self):
        if (auth := auth.load_cookie(self.env_get)):
            self._user_token = auth.value
            return self._user_token

    def _token_from_query(self):
        if token := self.queries.get('token'):
            self._user_token = token
            return self._user_token

    def _token_from_user(self):
        if self._user_token is not None:
            return self._user_token
        # token passed as query overrides local cookie
        if self._token_from_query() or self._token_from_cookie():
            return self._user_token

    @property
    def session(self):
        if self._session is None:
            if self._token_from_user():
                self._session = auth.get_by_token(self._user_token)
            else:
                return None
        return self._session

    @property
    def username(self):
        return self._session.username   if self.session else None

    @property
    def token(self):
        return self._session.token      if self.session else None

    @property
    def expiry(self):
        return self._session.expiry     if self.session else None

    # Attempt login using urelencoded credentials from request boy
    # or directly attempt login
    def launch(self, username='', password=''):
        if self.is_post_req():
            urldecode = lambda key: html.escape(str8(self.queries.get(make.encode(key), [b''])[0]))
            username = urldecode('username')
            password = urldecode('password')
        self._session = auth.login(username, password)
        if self.token:
            self.headers += auth.hdfor_cookie(self.token)
        return self.session is not None

    # Renew current sesssion and set user auth cookie accordingly
    def refuel(self):
        auth.del_by_username(self.username)
        self._session = auth.new_sesion_by_username(self.username)
        if self.session:
            self.extra_headers += auth.gen_cookie(self.token)
        return self.session

    # Logout of current session and clear user auth cookie
    def retire(self):
        self.extra_headers += auth.gen_cookie('auth', '')
        return auth.del_by_username(self.username)

    # Set appropriate headers
    def parse_content_type(self, content_type):
        match content_type.split('/'):
            case ['text', subtype]:
                self.headers += [('Content-Type', f'text/{subtype}')]
                if subtype == 'html':
                    self.format = self.format_html
            case ['auth', 'badreq']:
                self.headers += [('Auth-Status', 'Invalid Request')]
            case ['auth', 'badcreds']:
                self.headers += [('Auth-Status', 'Invalid Credentials')]
            case ['auth', auth_port]:
                self.headers += [('Auth-Status', 'OK'),
                                 ('Auth-Port',    auth_port),
                                 ('Auth-server', '127.0.0.1')]
            case _:
                return False
        return True

    def format_html(self, doc):
        # generate a reproduction of the original header without too much abstraction for initial version

        # general constants
        HR      = '<hr />'
        BR      = '<br />'
        APP_VERSION_SRC     = f'{APPLICATION} {VERSION} {SOURCE}'
        LINK_STYLE_CSS      = '<link rel="stylesheet" type="text/css" href="{self._cfg.style_get}"/>'
        META_CHARSET_UTF8   = '<meta charset="UTF-8">'

        # Prepare logo
        logo_div_doc  = ''
        logo_div_doc += make.img(self._cfg.logo_get, '[KDLP] logo', 'kdlp_logo')
        logo_div_doc += make.h('1', self._cfg.title, 'title')
        logo_div_gen  =  lambda: make.div('logo', logo_div_doc)

        # Prepare nav
        # FIXME: consider putting in config
        nav_kvs = self._cfg.NAV_BUTTONS
        nav_btn_gen =    lambda: ''.join([make.nav_button(pair[0], pair[1]) for pair in nav_kvs])
        nav_div_gen =    lambda: f'{HR}\n{make.div("nav", nav_btn_gen())}\n{HR}\n'

        # Prepare footer
        msg_doc  = ''
        msg_doc += [( 'whoami', self._cfg.whoami)]
        msg_doc += [('version', self._cfg.version)]
        msg_doc += [( 'source', self._cfg.source)]
        msg_doc += [(    'msg', self._cfg._msg)]
        msg_fmt = lambda kv: make.code(attrs='', c='{} = {}').format(*kv)
        msg_blk = lambda brdr, kvs: brdr + ''.join([msg_fmt(kv) for kv in kvs])

        # Concatenate all components to complete this format operation
        output = ''
        output += LINK_STYLE_CSS
        output += META_CHARSET_UTF8
        output += logo_div_gen()
        output += nav_div_gen()
        output += doc
        output += msg_blk(msg_doc)

        return output

    def respond(self, *content_desc):
        # Given total correctness of the server
        # all user requests end up here
        match content_desc:
            case (code, content_type, content) if self.parse_content_type(content_type):
                document = self.format(content)
            case _:
                self.parse_content_type('text/plain')
                code = http.HTTPStatus.INTERNAL_SERVER_ERROR
                document = 'ERROR: BAD RADIUS CONTENT DESCRIPTION'
        self._start_response(f'{code.value} {code.phrase}', self.headers)
        return [make.encode(document)]

form_welcome_template="""
	<div class="logout_info">
        <div class="logout_left">
        {}
        </div>

	<div class="logout_right">
        <h5> Welcome!</h5>
        </div>
	</div>

	<div class="logout_buttons">
    {}
	</div>
""".strip()

form_welcome_buttons="""
	<form id="logout" method="get" action="/login">
		<input type="hidden" name="logout" value="true">
		<button type="submit" class="logout">Logout</button>
	</form>
	<form id="renew" method="get" action="/login">
		<input type="hidden" name="renew" value="true">
		<button type="submit" class="renew">Renew</button>
	</form>
"""

form_login="""
	<form id="login" method="post" action="/login">
		<label for="username">Username:<br /></label>
		<input name="username" type="text" id="username" />
	<br />
		<label for="password">Password:<br /></label>
		<input name="password" type="password" id="password" />
	<br />
		<button type="submit">Submit</button>
	</form>
"""

def cookie_info_table(session):
    return table([
        ('Cookie Key', 'Value'),
        ('Token', session.token),
        ('User', session.username),
        ('Expiry', session.expiry_fmt),
        ('Remaining Validity', session.remaining_validity)])

def make_form_welcome(session):
    return form_welcome_template.format(cookie_info_table(session), logout_buttons())

form_register="""
    		<form id="register" method="post" action="/register">
                <label for="student_id">Student ID:</label>
                <input name="student_id" type="text" id="student_id" /><br />
                <button type="submit">Submit</button>
            </form>
""".strip()

def handle_welcome(rocket):
    makeme = make.form_welcome()
    match rocket.queries:
        case ('logout', 'true'):
            rocket.retire()
            rocket.msg(f'{rocket.username} logout')
            gen_form = make.form_login()
        case ('renew', 'true'):
            rocket.refuel()
            rocket.msg(f'{rocket.username} renew')
        case _:
            rocket.msg(f'{rocket.username} authenticated by token')
    return rocket.respond(HTTPStatus.OK, 'text/html', makeme())

def handle_login(rocket):
    if rocket.session:
        return handle_welcome()
    makeme = make.form_login()
    if  rocket.method == "POST":
        if rocket.launch():
            rocket.msg(f'{rocket.username} authenticated by password')
            makeme = make.form_welcome()
        else:
            rocket.msg(f'authentication failure')
    else:
        rocket.msg('welcome, please login')
    return rocket.respond(HTTPStatus.OK, 'text/html', makeme())

def handle_mail_auth(rocket):
    # This should be invariant when ngninx is configured properly
    mail_env_vars = ('HTTP_AUTH_USER' 'HTTP_AUTH_PASS', 'HTTP_AUTH_PROTOCOL', 'HTTP_AUTH_METHOD')
    [username, password, protocol, method] = [rocket.envget(key) for key in mail_env_vars]

    if not username or not password or protocol not in ('smtp', 'pop') or method != 'plain':
        return rocket.respond(HTTPStatus.BAD_REQUEST, 'auth/badreq', '')

    # A valid request with bad credentials returns OK
    if not rocket.launch(username, password):
        return rocket.respond(HTTPStatus.OK, 'auth/badcreds', '')

    # auth port depends on whether we are and lfx user and which service we are using
    auth_port = {
            False   : { 'smtp': '1465', 'pop': '1995' },
            True    : { 'smtp': '1466', 'pop': '1966' }
    }[rocket.forwho(username)][protocol]

    return rocket.respond(HTTPStatus.BAD_REQUEST, 'auth/badreq', '')

def handle_check(rocket):
    if rocket.token_from_query() and rocket.session:
        return rocket.respond(HTTPStatus.OK, 'text/plain', session.username)
    else:
        return rocket.respond(HTTPStatus.UNAVAILABLE_FOR_LEGAL_REASONS, 'text/plain', 'null')

def handle_logout(rocket):
    if rocket.queryget('username') and self.session:
        return rocket.respond(HTTPStatus.OK, 'text/plain', rocket.retire(self.username))
    else:
        return rocket.respond(HTTPStatus.UNAVAILABLE_FOR_LEGAL_REASONS, 'text/plain', 'null')

def handle_dashboard(rocket):
    return rocket.respond(HTTPStatus.OK, 'text/html', dash.dash(rocket.user))

def handle_stub(rocket, more=[]):
        make_cont = lambda meth_path: f'<h3>Developmennt sub for {meth_path} </h3>{"".join(more)}'
        meth_path = f'{rocket.method()} {rocket.path_info}'
        return rocket.respond(HTTPStatus.OK, 'text/plain', make_cont(meth_path))

def handle_register(rocket):
    return handle_stub(rocket, [f'{make.code(OLD_NOTES)}'])

# TODO: use this to implement register
_OLD_NOTES="""
	form_data = parse_qs(env['wsgi.input'].read(int(env['CONTENT_LENGTH'])))
	print(form_data)
	if b'student_id' not in form_data or len(form_data[b'student_id']) != 1:
		start_response('400 Bad Request', [('Content-Type', 'text/html')])
		return '<h1>Bad Request</h1><br>\n'
	result = accounts_db_exec(FIND_ACCOUNT_QUERY % escape(str(form_data[b'student_id'][0],'utf-8')))
	if not result:
		start_response('200 OK', [('Content-Type', 'text/html')])
		return '<h1>No such user</h1><br>\n'
	((id, username, password),) = result
	accounts_db_exec(DELETE_ACCOUNT_QUERY % id, commit=True)
	start_response('200 OK', [('Content-Type', 'text/html')])
	return f'''\
	<h1>Save these credentials, you will not be able to access them again</h1><br>
	<h3>Username: {username}</h1><br>
	<h3>Password: {password}</h1><br>
    return rocket.respond(sql.form_register())
""".strip()

def handle_md(rocket, md_path):
    with open(md_path, 'r', newline='') as f:
        content = markdown.markdown(f.read(), extensions=['tables', 'fenced_code'])
        return rocket.respond(HTTPStatus.OK, 'text/html', content)

def handle_try_md(rocket):
    md_path = f'{rocket.root}{rocket.path_info}'
    if re.match("^(?!/cgit)(.*\.md)$", rocket.path_info) and os.access(md_path, os.R_OK):
        return handle_md(rocket, md_path)
    else:
        return rocket.respond(HTTPStatus.NOT_FOUND, 'text/html', 'HTTP 404 NOT FOUND')

import config

def application(env, SR):
    rocket = Rocket(env, SR, config)
    if re.match("^(/login|/check|/logout/|/mail_auth)", rocket.path_info):
        return handle_login(rocket)
    elif re.match("^/dashboard", rocket.path_info):
        return handle_dashboard(rocket)
    elif re.match("^/register", rocket.path_info):
        return handle_register(rocket)
    else:
        return handle_try_md(rocket)
