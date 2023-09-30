#!/bin/env python3

import markdown, os, sys, re
import orbit, auth, orbgen, dashboard

from http import HTTPStatus

def handle_welcome(rocket):
    gen_form = orbgen.form_welcome
    match rocket.queries:
        case ('logout', 'true'):
            rocket.retire()
            rocket.msg(f'{rocket.username} logout')
            gen_form = orbgen.form_login()
        case ('renew', 'true'):
            rocket.refuel()
            rocket.msg(f'{rocket.username} renew')
        case _:
            rocket.msg(f'{rocket.username} authenticated by token')
    return rocket.respond(HTTPStatus.OK, 'text/html', gen_form())

def handle_login(rocket):
    if rocket.session:
        return handle_welcome()
    gen_form = orbgen.form_login
    if  rocket.method == "POST":
        if rocket.launch():
            rocket.msg(f'{rocket.username} authenticated by password')
            gen_form = orbgen.form_welcome
        else:
            rocket.msg(f'authentication failure')
    else:
        rocket.msg('welcome, please login')
    return rocket.respond(HTTPStatus.OK, 'text/html', orbgen.gen_form())

def handle_mail_auth(rocket):
    # This should be invariant when ngninx is orbcfgured properly
    mail_env_vars = ('HTTP_AUTH_USER' 'HTTP_AUTH_PASS', 'HTTP_AUTH_PROTOCOL', 'HTTP_AUTH_METHOD')
    [username, passwprd, protocol, method] = [rocket.envget(key) for key in mail_env_vars]

    if not username or not password or protocol not in ('smtp', 'pop') or method != 'plain':
        return rocket.respond(HTTPStatus.BAD_REQUEST, 'auth/badreq', '')

    # A valid request with bad credentials returns OK
    if not rocket.launch(username, password):
        return rocket.respond(HTTPStatus.OK, 'auth/badcreds', '')

    # auth port depends on whether we are and lfx user and which service we are using
    auth_port = {
            False   : { 'smtp': '1465', 'pop': '1995' },
            True    : { 'smtp': '1466', 'pop': '1966' }
    }[get_lfx_status(username)][protocol]

    return rocket.respond(HTTPStatus.BAD_REQUEST, 'auth/badreq', '')

def handle_check(rocket):
    if rocket.token_from_query() and rocket.session:
        return rocket.respond(HTTPStatus.OK, 'text/plain', session.username)
    else:
        return rocket.respond(HTTPStatus.UNAVAILABLE_FOR_LEGAL_REASONS, 'text/plain', 'null')

def handle_logout(rocket):
    if rocket.queryget('username') and self.session:
        return rocket.respond(HTTPStatus.OK, 'text/plain',
            auth.del_by_username(self.username))
    else:
        return rocket.respond(HTTPStatus.UNAVAILABLE_FOR_LEGAL_REASONS, 'text/plain', 'null')

def handle_dashboard(rocket):
    return rocket.respond(HTTPStatus.OK, 'text/html', dashboard.dashboard(rocket.user))

def handle_stub(rocket, more=[]):
        make_cont = lambda meth_path: f'<h3>Developmennt sub for {meth_path} </h3>{"".join(more)}'
        meth_path = f'{rocket.method()} {rocket.path_info}'
        return rocket.respond(HTTPStatus.OK, 'text/plain', make_cont(meth_path))

def handle_register(rocket):
    return handle_stub(rocket, [f'{orbgen.code(OLD_NOTES)}'])

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
    return rocket.respond(orbgen.form_register())
""".strip()

def handle_md(rocket, md_path):
    with open(md_path, 'r', newline='') as f:
        content = markdown.markdown(f.read(), extensions=['tables', 'fenced_code'])
        return rocket.respond(HTTPStatus.OK, 'text/html', content)

def try_handle_md(rocket):
    md_path = f'{orbit.DATA_ROOT}{rocket.path_info}'
    if re.match("^(?!/cgit)(.*\.md)$", rocket.path_info) and os.access(md_path, os.R_OK):
        return handle_md(rocket, md_path)
    else:
        return rocket.respond(HTTPStatus.NOT_FOUND, 'text/html', 'HTTP 404 NOT FOUND')
