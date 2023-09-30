#!/bin/env python3
#
# radius_config.py: configuration and constant definition

class constants:
    whoami   = 'radius'
    version  = '0.1'
    source   = 'https://github.com/underground-software/radius'

class configurable:
    # make exernal GET request to find these documents
    logo_photo_get  = '/kdlp.png'
    stylesheet_get  = '/style.css'

    # read these documents from a filesystem path
    dataroot   = f'{os.environ.get("ORBIT_PREFIX")}{os.environ.get("ORBIT_HOST")}'
    # TODO: this will become /var/orbit/databse/orbit.db or something
    database    = 'orbit.db'

    # duration of authentication token validity period
    ses_mins   = 180

    nav_buttons = [
        (       '/index.md', 'Home'     ),
        ('/course/index.md', 'Course'   ),
        (          '/login', 'Login'    ),
        (       '/register', 'Register' ),
        (      '/dashboard', 'Dashboard'),
        (         '/who.md', 'Who'      ),
        (        '/info.md', 'Info'     ),
        (           '/cgit', 'Git'      )]:
