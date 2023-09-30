# wsgi: entry point for uwsgi 

import re
import radius

def application(env, SR):
    rocket = radius.rock.rocket(env, SR)
    if re.match("^(/login|/check|/logout/|/mail_auth)", rocket.path_info):
        return radius.hand.le_login(rocket)
    elif re.match("^/dashboard", rocket.path_info):
        return radius.hand.le_dashboard(rocket)
    elif re.match("^/register", rocket.path_info):
        return radius.hand.le_register(rocket)
    else:
        return radius.hand.le_md(rocket)
