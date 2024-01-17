#!/bin/env python3
#
# it's all one things now

import bcrypt
import hashlib
import html
import markdown
import os
import re
import subprocess
from http import HTTPStatus, cookies
from datetime import datetime, timedelta
from urllib.parse import parse_qs

# === internal imports & constants ===
import config
import db

sec_per_min = 60
min_per_ses = config.minutes_each_session_token_is_valid

# === utilities ===


def encode(dat): return bytes(dat, "UTF-8")
def decode(dat): return str(dat, "UTF-8")


def mk_table(row_list, indentation_level=0):
    # Create <th> elements in first row, and <td> elements afterwards
    first_row = True
    def indenter(adjustment): return '\t' * (indentation_level + adjustment)

    output = f'{indenter(0)}<table>'
    for row in row_list:
        output += f'{indenter(1)}<tr>'
        for column in row:
            if first_row:
                output += f'{indenter(2)}<th>{column}</th>'
                first_row = False
            else:
                output += f'{indenter(2)}<td>{column}</td>'
        output += f'{indenter(1)}</tr>'
    output += f'{indenter(0)}</table>'

    return output


# === user session handling ===

class Session:
    """
    Session: User session management
             precondition for construction: validated authentication
             Manages the sessions db table
             construct with username to create a new session
             construct with environment to try load an active session

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

    expired()
        Get truth of whether this $self.expiry is in the past

    expiry_fmt()
        Get a printable, formatted string of $self.expiry

    expiry_dt() : datetime.datetime
        Current session's expiration as unix timestamp

    """

    def __init__(self, env=None, username=None):
        self.token = None
        self.username = None
        self.expiry = None

        # initialize session from username and add new database entry
        if username:
            self.username = username
            self.token = self.mk_hash(username)
            self.expiry = datetime.utcnow() + timedelta(minutes=min_per_ses)

            if db.ses_getby_username(username):
                db.ses_delby_username(username)
            db.ses_ins((self.token, self.username, self.expiry_ts()))

        # try to load active session from database using user token
        else:
            if (raw := env.get("HTTP_COOKIE", None)):
                cok = cookies.BaseCookie('')
                cok.load(raw)
                res = cok.get('auth', cookies.Morsel()).value

                if (ses_found := db.ses_getby_token(res)[0]):
                    self.token = ses_found[0]
                    self.username = ses_found[1]
                    self.expiry = datetime.fromtimestamp(ses_found[2])

    def end(self):
        res = db.ses_delby_token(self.token)
        self.token = None
        self.username = None
        self.expiry = None
        return res

    def valid(self):
        if not self.expired():
            return self.token

    def mk_hash(self, username):
        hash_input = username + str(datetime.now())
        return hashlib.sha256(encode(hash_input)).hexdigest()

    def expired(self):
        if (expiry := self.expiry) is None or datetime.utcnow() > expiry:
            self.end()
            return True
        else:
            return False

    def expiry_fmt(self):
        return self.expiry.strftime('%a, %d %b %Y %H:%M:%S GMT')

    def expiry_ts(self):
        return self.expiry.timestamp()

    def mk_cookie_header(self):
        if self.token is None:
            return [('Set-Cookie', 'auth=')]
        cookie_fmt = 'auth={}; Expires={}; Max-Age={}; Path=/'
        max_age = sec_per_min * min_per_ses
        cookie_val = cookie_fmt.format(self.token, self.expiry_fmt(), max_age)

        return [('Set-Cookie', cookie_val)]

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
        Dictionary of queries parsed from client URL

    session : Session
        The current valid session token if it exists or None

    username : string
        The valid current session username or None if unauthenticated

    token : string
        The valid current session token or None if unauthenticated

    expiry : datetime.datetime
        The current session's expiry time and date or None if unauthenticated

    Methods
    -------

    expiry_fmt()
        returns a printable and nicely formatted expiry date and time string

    """

    # Eventually, toggle CGI or WSGI
    def read_body_args_wsgi(self):
        if self.method == "POST":
            return parse_qs(self.env['wsgi.input'].read(self.len_body()))
        else:
            return {None: '(no body)'}

    def __init__(self, env, start_response):
        self.env = env
        self._start_response = start_response
        self.path_info = self.env.get("PATH_INFO", "/")
        self.queries = parse_qs(self.env.get("QUERY_STRING", ""))
        self._session = None
        self._msg = "(silence)"
        # HTTP response headers specified by list of string pairs
        self.headers = []
        self.body_args = self.read_body_args_wsgi()

    def __repr__(self):
        return (
            f'Rocket({self.method},{self.path_info},{self.queries},'
            f'{str(self.headers)},{self._msg},{str(self.session)},'
            f'{self.body_args})'
        )

    def __str__(self):
        return repr(self)

    def msg(self, msg):
        self._msg = msg

    def len_body(self):
        return int(self.env.get('CONTENT_LENGTH', "0"))

    @property
    def method(self):
        return self.env.get('REQUEST_METHOD', "GET")

    # when we use a session, check if the user has a token for
    # an existing session and act quietly load it if so
    # we don't do it in __init__ since that runs for public pages
    @property
    def session(self):
        if self._session is None:
            self._session = Session(env=self.env)
        # if the session is invalid, clear the user cookie
        if not self._session.valid():
            self.headers += self._session.mk_cookie_header()
        else:
            return self._session

    @property
    def username(self):
        if session := self.session:
            return session.username

    @property
    def token(self):
        if session := self.session:
            return session.token

    @property
    def expiry(self):
        if session := self.session:
            return session.expiry

    def body_args_query(self, key):
        return html.escape(
            decode(self.body_args.get(encode(key), [b''])[0]))

    # Attempt login using urelencoded credentials from request body
    def launch(self):
        new_ses = None
        if self.method == "POST":
            username = self.body_args_query('username')
            password = self.body_args_query('password')
            if (pwdhash := db.usr_pwdhashfor_username(username)[0]) and \
                    bcrypt.checkpw(encode(password), encode(pwdhash[0])):
                new_ses = Session(username=username)
            if new_ses:
                self._session = new_ses
                self.headers += self._session.mk_cookie_header()
            return self.session

    # Logout of current session and clear user auth cookie
    def retire(self):
        self._session.end()
        self.headers += self._session.mk_cookie_header()

    def format_html(self, doc):
        # loads cookie if exists
        self.session

        output = '<!DOCTYPE html>\n'
        output += '<html lang="en">\n'
        output += '<head>\n'

        # metadata
        output += '<link rel="stylesheet" type="text/css"'
        output += f' href="{config.style_get}">\n'
        output += '<meta charset="UTF-8">\n'
        output += '<meta name="viewport" content="width=device-width,'
        output += ' initial-scale=1.0">\n'
        output += '<title>KDLP</title>\n'

        output += '</head>\n'
        output += '<body>\n'

        # body header: logo and title
        output += '<div class="logo">\n'
        output += f'<img src="{config.logo_get}" alt="logo" class="logo">\n'
        output += f'<h1 class="title">{config.title}</h1>\n'
        output += '</div>\n'

        # body header: navigation bar
        output += '<hr>\n'
        output += '<div class="nav">\n'
        output += '\n'.join([f'<a href="{pair[0]}" class="nav">{pair[1]}</a>'
                             for pair in config.nav_buttons])
        output += '</div>\n'
        output += '<hr>\n'

        # body: the main page content
        output += doc

        # body footer
        output += '<hr>\n'
        output += f'<code>msg = {self._msg}</code><br>\n'
        output += f'<code>whoami  = {self.username}</code><br>\n'
        output += f'<code>{config.appname} {config.version}'
        output += f' {"in development" if not config.production else ""}'
        output += f' {config.source}</code>\n'
        output += '<hr>\n'

        output += '</body>\n'
        output += '</html>\n'

        return output

    def respond(self, response_code, response_document, mail_auth=False):
        # Given total correctness of the server
        # all user requests end up here
        if not mail_auth:
            self.headers += [('Content-Type', 'text/html')]
            response_document = self.format_html(response_document)
        self._start_response(f'{response_code.value} {response_code.phrase}',
                             self.headers)
        return [encode(response_document)]


form_welcome_template = """
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

form_welcome_buttons = """
    <form id="logout">
        <input class="logout" type="button" onclick="location.href='/logout';" value="Logout" />
    </form>
""".strip()  # NOQA: E501

form_login = """
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

form_logout = """
<head>
    <meta http-equiv="Refresh" content="0; URL=/login" />
</head>
"""


def cookie_info_table(session):
    return mk_table([
        ('Cookie Key', 'Value'),
        ('Token', session.token),
        ('User', session.username),
        ('Expiry', session.expiry_fmt()),
        ('Remaining Validity', str(session.expiry - datetime.utcnow()))])


def mk_form_welcome(session):
    return form_welcome_template.format(cookie_info_table(session),
                                        form_welcome_buttons)


form_register = """
    <form id="register" method="post" action="/register">
        <label for="student_id">Student ID:</label>
        <input name="student_id" type="text" id="student_id" /><br />
        <button type="submit">Submit</button>
    </form>
""".strip()


def handle_login(rocket):
    response_document = form_login
    response_status = HTTPStatus.OK
    if rocket.session:
        rocket.msg(f'{rocket.username} authenticated by token')
        response_document = mk_form_welcome(rocket.session)
    elif rocket.method == "POST":
        if rocket.launch():
            rocket.msg(f'{rocket.username} authenticated by password')
            response_document = mk_form_welcome(rocket.session)
        else:
            rocket.msg('authentication failure')
            response_status = HTTPStatus.UNAUTHORIZED
    else:
        rocket.msg('welcome, please login')
        response_document = form_login
    return rocket.respond(response_status, response_document)


def handle_mail_auth(rocket):
    # This should be invariant when ngninx is configured properly
    mail_env_vars = ('HTTP_AUTH_USER', 'HTTP_AUTH_PASS',
                     'HTTP_AUTH_PROTOCOL', 'HTTP_AUTH_METHOD')
    [username, password, protocol, method] = [rocket.env.get(key)
                                              for key in mail_env_vars]

    if not username or not password \
            or protocol not in ('smtp', 'pop3') \
            or method != 'plain':
        rocket.headers += [('Auth-Status', 'Invalid Request')]
        return rocket.respond(HTTPStatus.BAD_REQUEST, '', mail_auth=True)

    # Strange, but a request in valid form with bad credentials returns OK
    if (pwdhash := db.usr_pwdhashfor_username(username)[0]) is None \
            or not bcrypt.checkpw(encode(password), encode(pwdhash[0])):
        rocket.headers += [('Auth-Status', 'Invalid Credentials')]
        return rocket.respond(HTTPStatus.OK, '', mail_auth=True)

    # The authentication port depends on whether we are an lfx user
    # and which service we are using. FIXME: redesign this area
    instance = ['DFL', 'LFX'][
            int(db.usr_getif_lfx_username(username)[0][0]) != 0]
    auth_port = {
            'DFL': {'smtp': '1465', 'pop3': '1995'},
            'LFX': {'smtp': '1466', 'pop3': '1966'}
    }[instance][protocol]

    rocket.headers += [('Auth-Status', 'OK'),
                       ('Auth-Port',    auth_port),
                       ('Auth-Server', '127.0.0.1')]
    return rocket.respond(HTTPStatus.OK, '', mail_auth=True)


def handle_logout(rocket):
    if rocket.session:
        rocket.retire()
    return rocket.respond(HTTPStatus.OK, form_logout)


def handle_dashboard(rocket):
    return handle_stub(rocket, ['dashboard in development, check back later'])


def handle_stub(rocket, more=[]):
    meth_path = f'{rocket.method} {rocket.path_info}'
    content = f'<h3>Development stub for {meth_path} </h3>{"".join(more)}'
    return rocket.respond(HTTPStatus.OK, content)


def handle_register(rocket):
    return handle_stub(rocket, [f'<code><br />{_OLD_NOTES}</code><br />'])


def handle_cgit(rocket):
    cgit_env = os.environ.copy()
    cgit_env['PATH_INFO'] = rocket.path_info.split('/cgit')[1]
    proc = subprocess.Popen(['/usr/share/webapps/cgit/cgit'],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            env=cgit_env)
    so, se = proc.communicate()
    outstring = str(so, 'UTF-8')
    outstring = outstring.split('\n\n', 1)[1]
    return rocket.respond(HTTPStatus.OK, outstring)


# TODO: use this to implement register FIXME
_OLD_NOTES = """
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
""".strip()  # NOQA: E501


def handle_md(rocket, md_path):
    with open(md_path, 'r', newline='') as f:
        content = markdown.markdown(f.read(),
                                    extensions=['tables', 'fenced_code'])
        return rocket.respond(HTTPStatus.OK, content)


def handle_try_md(rocket):
    md_path = f'{config.doc_root}{rocket.path_info}'
    if re.match("^(?!/cgit)(.*\\.md)$", rocket.path_info) \
            and os.access(md_path, os.R_OK):
        return handle_md(rocket, md_path)
    else:
        return rocket.respond(HTTPStatus.NOT_FOUND, 'HTTP 404 NOT FOUND')


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
    elif re.match("^/cgit", rocket.path_info):
        return handle_cgit(rocket)
    else:
        return handle_try_md(rocket)
