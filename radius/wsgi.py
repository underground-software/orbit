import radius

def application(env, SR):
    rocket = radius.rocket(env, SR)
    if re.match("^(/login|/check|/logout/|/mail_auth)", rocket.path_info):
        return radius.dispatch.handle_login(rocket)
    elif re.match("^/dashboard", rocket.path_info):
        return radius.dispatch.handle_dashboard(rocket)
    elif re.match("^/register", rocket.path_info):
        return radius.dispatch.handle_register(rocket)
    else:
        return radius.dispatch.try_handle_md(rocket)
