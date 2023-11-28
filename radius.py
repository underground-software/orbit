#!/bin/env python3
#
# it's all one things now

from http import HTTPStatus, cookies
import markdown, os, re
import sys, bcrypt, hashlib
from datetime import datetime, timedelta
from urllib.parse import parse_qs
import html
import config as cfg
import db

sec_per_min = 60
min_per_ses = cfg.ses_mins

# utilities

encode    = lambda dat: bytes(dat, "UTF-8")
decode    = lambda dat: str(dat, "UTF-8")

# HTML helpers

# shorthand key:
# c := content within the tag
# s := tag class
# h := href or src link
# i := indentation level
# a := full attribute string
# l := list to insert between subtags

# indent string c with i tabs and append newline
mk_t      = lambda c, i=0    : '\t'*i + f'{c}\n'
#def mk_t(c, i=0):
    #print("mk_t", i, c, file=sys.stderr)
    #return '\t'*i + f'{c}<br />'


# generalized attribute inserters
mk_dtattr = lambda t, c, a='', i=0: mk_t(f'<{t}{a}>{c}</{t}>', i)
mk_otattr = lambda t, a='', i=0: mk_t(f'<{t}{a} />', i)


# fallback class for generated HTML
cdfl = 'radius_default'

# for simple usage, take just the class
mk_dubtag = lambda t, c, s=cdfl, i=0: mk_dtattr(t, c, f' class="{s}"', i=i)

# no conent so just take tag and class
mk_onetag = lambda t, s=cdfl, i=0: mk_t(f'<{t} class="{s}" />', i=i)

# direct HTML tag makers
mk_h    = lambda v, c, s=cdfl, i=0: mk_dubtag("h" + str(v), c, s, i)
mk_li   = lambda            c, i=0: mk_dubtag("li", c, i)
_lihelp = lambda            l, i=0: '\n'.join([mk_li(_li, i) for _li in k])

# for blocks with indented content in  a\n\t\b\c form
_3linefmt = '{}\n{}\n{}'
mk_tblock = lambda a, b, c, i=0: _3linefmt.format(mk_t(a, i), mk_t(b, i+1), mk_t(c, i))

mk_ul   = lambda            l, i=0: mk_tblock("<ul>", _lihelp(l, i+1), "</ul>", i)


_afmt = ' href="{}" class="{}"'
mk_a    = lambda h, t, s=cdfl, i=0: mk_dtattr("a", t, _afmt.format(h, s), i)
mk_code = lambda    c, s=cdfl, i=0: mk_dubtag("code", c, s, i)

# x used for alt text attribute value
_imgfmt = ' src="{}" class="{}" alt="{}"'
mk_img  = lambda h, x, s=cdfl, i=0: mk_otattr("img", _imgfmt.format(h, s, x) , i)

# no default class for div: it's required as the first argument
_divfmt = '<div class="{}">'
mk_div  = lambda         s, c, i=0: mk_tblock(_divfmt.format(s), c, "</div>")


# pass h=1 for table header
mk_td   = lambda    c, s, h=0, i=0: mk_dubtag(f't{["d","h"][h]}', c, s, i)

_trhelp = lambda      l, s, h, i=0: '\n'.join([mk_td(_td, s, h, i) for _td in l])
mk_tr   = lambda      l, s, h, i=0: mk_tblock("<tr>", _trhelp(l, s, h, i+1), "</tr>", i)

_tbhelp = lambda         l, s, i=0: '\n'.join([mk_tr(_tr, s, j == 0, i) for j, _tr  in enumerate(l)])
mk_tbl  = lambda    l, s=cdfl, i=0: mk_tblock("<table>", _tbhelp(l, s, i), "</table>")

# compound HTML makers
mk_sep    = lambda         i=0: mk_t(f'<hr />', i)
mk_chrset = lambda         i=0: mk_t('<meta charset="UTF-8">', i)
mk_msgfmt = lambda     kv, i=0: mk_code(('{} = {} <br />').format(*kv), i)
mk_msgblk = lambda b, kvs, i=0: b + ''.join([mk_msgfmt(kv, i) for kv in kvs]) + b
_stylefmt = '<link rel="stylesheet" type="text/css" href="{}"/>'
mk_style  = lambda         i=0: mk_t(_stylefmt.format(cfg.style_get), i)
mk_navbt  =  lambda  h, t, i=0: mk_a(t, h, 'nav')

# === user session handling === 

class Session:
    """
    Session: User session management assuming authentication handled by caller
             Manages the sessions db table
             construct with username to create a new session
             construct with environment and queries to try load existing session

    ...

    Attributes
    ----------
    
    username : string
        The authenticated  username if self.valid()
        None otherwise

    token : string
        A valid token for user session if self.valid()
        None otherwise

    expiry : datetime.datetime
        The current session expiration date  if self.valid()
        None otherwise


    Methods
    -------
    valid()
        Get truth of whether this session is valid at time of call

    extend()
        If the session is valid, reset expiry to $mins_per_ses

    expired()
        Get truth of whether this $self.expiry is in the past

    expiry_fmt()
        Get a printable, formatted string of $self.expiry

    expiry_dt() : datetime.datetime
        Current session's expiration as unix timestamp

    """
    # attempt to continue existing session using a token or query
    def __init__(self, env=None, queries=None, username=None):
        self.token      = None
        self.username   = None
        self.expiry     = None


    # initialize session from username and add new record
        if username:
            self.username   = username
            self.token      = self.mk_hash(username)
            self.expiry     = datetime.utcnow() + timedelta(minutes=min_per_ses)
            if db.ses_getby_username(username):
                db.ses_delby_username(username)
            db.ses_ins((self.token, self.username, self.expiry_ts()))
        else:
            # query overrides cookie
            if (res := queries.get('token', None)):
                pass
            elif (raw := env.get("HTTP_COOKIE", None)):
                cok = cookies.BaseCookie('')
                cok.load(raw)
                res  = cok.get('auth', cookies.Morsel()).value
            if (ses_found := db.ses_getby_token(res)[0]):
                self.token      = ses_found[0]
                self.username   = ses_found[1]
                self.expiry     = datetime.fromtimestamp(ses_found[2])

    def extend(self):
        if self.valid():
            self.expiry = datetime.utcnow() + timedelta(minutes=min_per_ses)
            db.ses_setexpiry_token((self.expiry.timestamp(), self.token))

    def end(self):
        return db.ses_delby_token(self.token)

    def valid(self):
        return self.token and not self.expired()

    def mk_hash(self, username):
        hash_input = username + str(datetime.now())
        return hashlib.sha256(encode(hash_input)).hexdigest()

    def expired(self):
        if (expiry := self.expiry) is None or datetime.utcnow() > expiry:
            db.ses_delby_token(self.token)
            return True
        else:
            return False

    def expiry_fmt(self):
        return self.expiry.strftime('%a, %d %b %Y %H:%M:%S GMT')

    def expiry_ts(self):
        return self.expiry.timestamp()

    def mk_cookie_header(self):
        print("MAKE COOKIE HEADER", self.token)
        if self.token is None:
            return [('Set-Cookie', '')]
        cookie_fmt = 'auth={}; Expires={}; Max-Age={}; Path=/'
        max_age = sec_per_min * min_per_ses
        cookie_val = cookie_fmt.format(self.token, self.expiry_fmt(), max_age)

        return  [('Set-Cookie', cookie_val)]

    def __repr__(self):
        return f'Session({self.token},{self.username},{self.expiry})'

    def __str__(self):
        return repr(self)

class Rocket:
    """
    Rocket: Radius user request context (responsible for authentication)
            Limited external read access to users table

    ...

    Attributes
    ----------
    path_info : str
        Absolute path requested by user

    queries : dict
        Dictionary of parsed URL queries (passsed by '?key1=value1&key2=value2' suffix)

    session : Session
        The current valid session token if it exists or None

    username : string
        The valid current session username or None if unauthenticated

    token : string
        The valid current session token or None if unauthenticated

    expiry : datetime.datetime
        The current session's expiration time and date or None if unauthenticated

    Methods
    -------

    expiry_fmt()
        returns a printable and nicely formatted expiry date and time string

    """

    # Eventually, toggle CGI or WSGI
    def read_body_args_wsgi(self):
        if self.method == "POST":
	        return  parse_qs(self.env['wsgi.input'].read(self.len_body()))
        else:
            return {None: '(no body)'}


    def __init__(self, env, start_res):
        self.env   = env
        self._start_res = start_res
        self.path_info = self.env.get("PATH_INFO", "/")
        self.queries   = parse_qs(self.env.get("QUERY_STRING", ""))
        self._session   = None
        self._msg       = "(silence)"
        # list of tuple string pairs to reutrn as HTTP response headers
        self.headers   = []
        # enable page formatter selection
        # right now we just make the header and footer for HTML
        # and user the identity function by default
        self.format    = lambda x: x
        self.body_args  = self.read_body_args_wsgi()

    def __repr__(self):
        return f'Rocket({self.method},{self.path_info},{self.queries},{str(self.headers)},{self._msg},{str(self.session)},{self.body_args})'

    def __str__(self):
        return repr(self)

    def msg(self, msg):
        self._msg = msg

    def len_body(self):
        return int(self.env.get('CONTENT_LENGTH', "0"))

    @property
    def method(self):
        return self.env.get('REQUEST_METHOD', "GET")

    # when we use a session, check if the user supplied a token for
    # an existing session and act quietly load it if so
    # we don't do it in __init__ since that runs for public pages
    @property
    def session(self):
        if self._session is None:
            self._session = Session(env=self.env, queries=self.queries)
        return self._session if self._session.valid() else None

    @property
    def username(self):
        return self._session.username   if self._session else None

    @property
    def token(self):
        return self._session.token      if self._session else None

    @property
    def expiry(self):
        return self._session.expiry     if self._session else None

    # Attempt login using urelencoded credentials from request body
    def launch(self):
        new_ses = None
        if self.method == "POST":
            urldecode = lambda key: html.escape(decode(self.body_args.get(encode(key), [b''])[0]))
            username = urldecode('username')
            password = urldecode('password')
            if (pwdhash := db.usr_pwdhashfor_username(username)[0]) and \
                bcrypt.checkpw(encode(password), encode(pwdhash[0])):
                    new_ses = Session(username=username)
            if new_ses:
                self._session = new_ses
                self.headers += self._session.mk_cookie_header()
            return self.session

    # Renew current sesssion and set user auth cookie accordingly
    def refuel(self):
        if self.session:
            self._session.extend()
            self.headers += self._session.mk_cookie_header()
        return self.session

    # Logout of current session and clear user auth cookie
    def retire(self):
        self._session.end()
        self.headers += self._session.mk_cookie_header()

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
                                 ('Auth-Server', '127.0.0.1')]
            case _:
                return False
        return True

    def format_html(self, doc):
        # generate a reproduction of the original header without too much abstraction for initial version

        # general constants

        # Prepare logo
        logo_div_doc  = ''
        logo_div_doc += mk_img(cfg.logo_get, '[KDLP] logo', 'kdlp_logo')
        logo_div_doc += mk_h('1', cfg.title, 'title')
        logo_div_gen  =  lambda: mk_div('logo', logo_div_doc)

        # Prepare nav
        nav_kvs = cfg.nav_buttons
        nav_btn_gen =    lambda: ''.join([mk_navbt(pair[1], pair[0]) for pair in nav_kvs])
        nav_div_gen =    lambda: f'<hr />{mk_div("nav", nav_btn_gen())}{mk_sep()}\n'

        # loads cookie if exists
        self.session

        # Prepare footer
        msgdoc  = []
        msgdoc += [(    'msg',  self._msg)]
        msgdoc += [('whoami',   self.username)]
        msgdoc += [('appname',  cfg.appname)]
        msgdoc += [('version',  cfg.version)]
        msgdoc += [('source',   cfg.source)]
        # Concatenate all components to complete this format operation
        output = ''
        output += mk_style()
        output += mk_chrset()
        output += logo_div_gen()
        output += nav_div_gen()
        output += doc
        output += mk_msgblk(mk_sep(), msgdoc)

        return output

    def respond(self, *content_desc):
        # Given total correctness of the server
        # all user requests end up here
        match content_desc:
            case (code, content_type, content) if self.parse_content_type(content_type):
                document = self.format(content)
            case _:
                self.parse_content_type('text/plain')
                code = HTTPStatus.INTERNAL_SERVER_ERROR
                document = 'ERROR: BAD RADIUS CONTENT DESCRIPTION'
        print(f'respond {code.phrase} {self.headers} {document}')
        self._start_res(f'{code.value} {code.phrase}', self.headers)
        return [encode(document)]

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
    <form id="logout">
    <input class="logout" type="button" onclick="location.href='/logout';" value="Logout" />
    </form>
""".strip()

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
""".strip()

form_logout="""
<head>
  <meta http-equiv="Refresh" content="0; URL=/login" />
</head>
"""

def cookie_info_table(session):
    return mk_tbl([
        ('Cookie Key', 'Value'),
        ('Token', session.token),
        ('User', session.username),
        ('Expiry', session.expiry_fmt()),
        ('Remaining Validity', str(session.expiry - datetime.utcnow()))])

def mk_form_welcome(session):
    return form_welcome_template.format(cookie_info_table(session), form_welcome_buttons)

form_register="""
    		<form id="register" method="post" action="/register">
                <label for="student_id">Student ID:</label>
                <input name="student_id" type="text" id="student_id" /><br />
                <button type="submit">Submit</button>
            </form>
""".strip()

def handle_login(rocket):
    makeme = lambda: form_login
    if rocket.session:
        makeme = lambda : mk_form_welcome(rocket.session)
        rocket.msg(f'{rocket.username} authenticated by token')
        return rocket.respond(HTTPStatus.OK, 'text/html', makeme())
    if rocket.method == "POST":
        if rocket.launch():
            rocket.msg(f'{rocket.username} authenticated by password')
            makeme = lambda: mk_form_welcome(rocket.session)
        else:
            rocket.msg(f'authentication failure')
    else:
        rocket.msg('welcome, please login')
    return rocket.respond(HTTPStatus.OK, 'text/html', makeme())

def handle_mail_auth(rocket):
    # This should be invariant when ngninx is configured properly
    mail_env_vars = ('HTTP_AUTH_USER', 'HTTP_AUTH_PASS', 'HTTP_AUTH_PROTOCOL', 'HTTP_AUTH_METHOD')
    [username, password, protocol, method] = [rocket.env.get(key) for key in mail_env_vars]

    if not username or not password or protocol not in ('smtp', 'pop3') or method != 'plain':
        return rocket.respond(HTTPStatus.BAD_REQUEST, 'auth/badreq', '')

    # Strange, but a request in valid form with bad credentials returns OK
    if (pwdhash := db.usr_pwdhashfor_username(username)[0]) is None \
            or not bcrypt.checkpw(encode(password), encode(pwdhash[0])):
                return rocket.respond(HTTPStatus.OK, 'auth/badcreds', '')

    # auth port depends on whether we are and lfx user and which service we are using
    # this isn't actually handled in setup yet but that isn't too hard
    instance = ['DFL', 'LFX'][int(db.usr_getif_lfx_username(username)[0][0]) != 0]
    auth_port = {
            'DFL'   : { 'smtp': '1465', 'pop3': '1995' },
            'LFX'   : { 'smtp': '1466', 'pop3': '1966' }
    }[instance][protocol]

    return rocket.respond(HTTPStatus.OK, f'auth/{auth_port}', '')

def handle_logout(rocket):
    if rocket.session:
        rocket.retire()
    return rocket.respond(HTTPStatus.OK, 'text/html', form_logout)

def handle_dashboard(rocket):
    return handle_stub(rocket, ['dashboard in development, check back later'])

def handle_stub(rocket, more=[]):
        mk_cont = lambda meth_path: f'<h3>Development stub for {meth_path} </h3>{"".join(more)}'
        meth_path = f'{rocket.method} {rocket.path_info}'
        return rocket.respond(HTTPStatus.OK, 'text/html', mk_cont(meth_path))

def handle_register(rocket):
    return handle_stub(rocket, [f'<code><br />{_OLD_NOTES}</code><br />'])

# TODO: use this to implement register
_OLD_NOTES="""
	form_data = parse_qs(env['wsgi.input'].read(int(env['CONTENT_LENGTH'])))
	print(form_data)
	if b'student_id' not in form_data or len(form_data[b'student_id']) != 1:
		start_response('400 Bad Request', [('Content-Type', 'text/html')])
		return '\<h1\>Bad Request\</h1\>\<br\>\n'
	result = accounts_db_exec(FIND_ACCOUNT_QUERY % escape(str(form_data[b'student_id'][0],'utf-8')))
	if not result:
		start_response('200 OK', [('Content-Type', 'text/html')])
		return '\<h1\>No such user\</h1\>\<br\>\n'
	((id, username, password),) = result
	accounts_db_exec(DELETE_ACCOUNT_QUERY % id, commit=True)
	start_response('200 OK', [('Content-Type', 'text/html')])
	return f'''\
	\<h1\>Save these credentials, you will not be able to access them again\</h1\>\<br\>
	\<h3\>Username: {username}\</h1\>\<br\>
	\<h3\>Password: {password}\</h1\>\<br\>
    return rocket.respond(sql.form_register())
""".strip()

def handle_md(rocket, md_path):
    with open(md_path, 'r', newline='') as f:
        content = markdown.markdown(f.read(), extensions=['tables', 'fenced_code'])
        return rocket.respond(HTTPStatus.OK, 'text/html', content)

def handle_try_md(rocket):
    md_path = f'{cfg.dataroot}{rocket.path_info}'
    if re.match("^(?!/cgit)(.*\.md)$", rocket.path_info) and os.access(md_path, os.R_OK):
        return handle_md(rocket, md_path)
    else:
        return rocket.respond(HTTPStatus.NOT_FOUND, 'text/html', 'HTTP 404 NOT FOUND')

def application(env, SR):
    rocket = Rocket(env, SR)
    if re.match("^/login", rocket.path_info):
        return handle_login(rocket)   
    elif re.match("^/logout", rocket.path_info):
        return handle_logout(rocket)   
    elif re.match("^/mail_auth", rocket.path_info):
        return handle_mail_auth(rocket)
    elif re.match("^/dashboard", rocket.path_info):
        return handle_dashboard(rocket)
    elif re.match("^/register", rocket.path_info):
        return handle_register(rocket)
    else:
        return handle_try_md(rocket)
