# wsgi: entry point for uwsgi 

import re
import radius
import config

def application(env, SR):
    rocket = radius.rocket(env, SR, config)
    if re.match("^(/login|/check|/logout/|/mail_auth)", rocket.path_info):
        return radius.handle_login(rocket)
    elif re.match("^/dashboard", rocket.path_info):
        return radius.handle_dashboard(rocket)
    elif re.match("^/register", rocket.path_info):
        return radius.handle_register(rocket)
    else:
        return radius.handle_md(rocket)
