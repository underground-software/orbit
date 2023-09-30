#!/bin/env python3

# these are some sensible defaults

ORBIT_DB= 'orbit.db'

# this is broken for now unless there is an sms sender sitting at localhost:6060
TXT_ALERT 	= False
LOG_ALERT	= True
ALERT_LOGFILE 	= 'alert.log'

SESSION_MINS	= 60
SESSION_DAYS	= 0

# does a new login from the same account bump an old session off
# or do we prevent the new session from logging on?
NEW_SESSION_BUMPS_OLD   = True
