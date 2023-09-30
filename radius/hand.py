#!/bin/env python3

# hand: rocket handlers for each server request type
#       use "le_" prefix for "hand.le_..()" usage

from http import HTTPStatus
import markdown, os, sys, re
import make, auth, dash

def le_welcome(rocket):
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

def le_login(rocket):
    if rocket.session:
        return le_welcome()
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

def le_mail_auth(rocket):
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

def le_check(rocket):
    if rocket.token_from_query() and rocket.session:
        return rocket.respond(HTTPStatus.OK, 'text/plain', session.username)
    else:
        return rocket.respond(HTTPStatus.UNAVAILABLE_FOR_LEGAL_REASONS, 'text/plain', 'null')

def le_logout(rocket):
    if rocket.queryget('username') and self.session:
        return rocket.respond(HTTPStatus.OK, 'text/plain', rocket.retire(self.username))
    else:
        return rocket.respond(HTTPStatus.UNAVAILABLE_FOR_LEGAL_REASONS, 'text/plain', 'null')

def le_dashboard(rocket):
    return rocket.respond(HTTPStatus.OK, 'text/html', dash.dash(rocket.user))

def le_stub(rocket, more=[]):
        make_cont = lambda meth_path: f'<h3>Developmennt sub for {meth_path} </h3>{"".join(more)}'
        meth_path = f'{rocket.method()} {rocket.path_info}'
        return rocket.respond(HTTPStatus.OK, 'text/plain', make_cont(meth_path))

def le_register(rocket):
    return le_stub(rocket, [f'{make.code(OLD_NOTES)}'])

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

def le_md(rocket, md_path):
    with open(md_path, 'r', newline='') as f:
        content = markdown.markdown(f.read(), extensions=['tables', 'fenced_code'])
        return rocket.respond(HTTPStatus.OK, 'text/html', content)

def le_try_md(rocket):
    md_path = f'{rocket.root}{rocket.path_info}'
    if re.match("^(?!/cgit)(.*\.md)$", rocket.path_info) and os.access(md_path, os.R_OK):
        return le_md(rocket, md_path)
    else:
        return rocket.respond(HTTPStatus.NOT_FOUND, 'text/html', 'HTTP 404 NOT FOUND')
