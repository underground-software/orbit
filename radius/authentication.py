import sys, datetime, bcrypt, hashlib
from datetime import datetime

import radius

# Constants
sec_per_min = 60
_min_per_ses = radius.config.sesh_mins

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
            
    orbdbs.do_sessions_
    orbdbs.do_sessions_comm(orbdbs.SESSIONS_NEW, \
            Session(gen_tok_hsh(username), username, gen_expiry().timestamp()))

    return get_by_username(username)

def del_by_username(username):
    """
    auth.del_by_username: delete any extant valid session data for $username
        username : str
        |   lookup session for $username
    [return]
        | $token if this invocation sucessfully invalidates a corresponding valid session
        | None otherwise
    """
    return orbdbs.sessions_delete_by_username(username)

def del_by_token(token):
    """
    auth.del_by_token: delete any extant valid session data for $token
        token  : str
        |   lookup session for $token
    [return]
        | $token if this invocation sucessfully invalidates a corresponding valid session
        | None otherwise
    """
    return orbdbs.sessions_delete_by_token(token)

def get_by_username(username):
    """
    auth.get_by_username: get any extant valid session data for $username
        username : str
        |   lookup any sesion for $username
    [return]
        | session validated by $username if extant
        | None otherwise
    """
    return orbdbs.sessions_select_by_username(username)

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
    return orbdbs.sessions_select_by_token(token)

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
