#!/bin/bash

sqlite3 orbit.db ".read db.default" ".exit"

# do something with this for dev setup

#def autorefresh_text(interval):
#    return bytes(f'<meta http-equiv="refresh" content="{interval}">', "UTF-8")
