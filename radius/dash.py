#!/bin/env python

# builds the 'international student information system' html table

from datetime import datetime
import random
from sql import submissions_get_by_username, assignments_get_all

from orbgen import table

def dashboard_table(ass_pair, subd):
    fmt = [('Submission IDs', 'Time Recieved', 'Summary',  'Email IDs', 'Grade')]
    try:
        for subgroup in subd[ass_pair[0]]:
                fmt += [subgroup]
    except KeyError:
        pass

    try:
        for subgroup in subd[ass_pair[1]]:
            fmt += [subgroup]
    except KeyError:
        pass

    print('FMT:', str(fmt))
    return table(fmt)

# REVISION INDEX | DATETIME RECV | COMMENTS | GRADE
def dashboard(user):
    subs = submissions_get_by_username(user)
    print('GET SUBS', subs)
    subd = {}

    for sub in subs:
        if not sub[4] in subd:
            subd[sub[4]] = []
        subd[sub[4]] += [(sub[0], sub[2],
                sub[6].split(';')[0],
                "\n".join(sub[5].split(';')),
                random.choices(['A','B','C','D','F'])[0])]

    output =''
    output += f"<h1> {user}'s dashboard</h1>"

    print('SUBD:', subd)

    for ass_pair in assiginments_get_all():
        output += f'<h3>{ass_pair[0]}: {ass_pair[1]}</h3>\n'
        output += dashboard_table(ass_pair, subd)

    return output

def main():
    print(dashboard("joel"))

if __name__ == "__main__":
    main()
