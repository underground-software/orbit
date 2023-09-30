#!/bin/env python
import sys, os, email
from datetime import datetime
from common import add_sub, get_ass_by_email_id, get_ass_by_web_id

def new_sub(sub_id, user, timestamp, emails, email_ids):
    tos, frs, sbj = [], [], []
    for e in emails:
        tos += [e['X-KDLP-Orig-To'].split('@')[0].lower()]
        frs += [e['X-KDLP-Orig-From'].split('@')[0].split('<')[1].lower()]
        sbj += [e['Subject']]
    
    for f in frs:
        print(f"compare  {f} and {user}")
        if f != user:
            print(f'ata REJECT from:{f} != user:{user}', file=sys.stderr)
            return None
    for i in tos:
        # make sure this is a real assignment (check either name)
        # this is also validated at the triger level by exclusion
        # since we only provide servcies to trigger on changes to
        # the assignment dirs. This checks grades.db which
        # is initialized by setup.sh in mercury
        first_try=get_ass_by_email_id(i)
        second_try=get_ass_by_web_id(i)
        print("get assignment SQL\n",first_try, second_try, file=sys.stderr)

    print(f'ata ACCEPT from:{frs[0]} to:{tos[0]} user:{user} ts:{timestamp}', file=sys.stderr)
        
    return add_sub(sub_id, user, timestamp, frs, tos, email_ids, sbj)

def main():
    [sub_id, user, timestamp] = sys.argv[1:4]
    log_msg=f'{datetime.fromtimestamp(int(timestamp))} {sub_id} {user}'
    emails=[]
    email_ids=[]
    print(log_msg)
    # iterate over the triggering patchset
    trig = os.environ.get("TRIGGER_DIR")
    sub_path=f'{trig}/{sub_id}'
    with open(sub_path, 'r') as sub_file:
        print(f'reading from {sub_path}')

        # write to unconditional ata submission log
        with open(os.environ.get('ATA_LOG'), 'a') as ata_log_file:
            print(log_msg, file=ata_log_file)

        # write to ata assignment submission log
        with open(os.environ.get('SUB_LOG'), 'a') as sub_log_file:
            print(log_msg, file=sub_log_file)

        e = None
        i=0
        for line in sub_file.readlines():
            # skip first line with timestamp and user
            if i < 1:
                i=i+1
                continue
            with open(f'{os.environ.get("RAW_DIR")}/{line.strip().split(" ")[0]}', 'r') as mail_file:
                e = email.message_from_file(mail_file)
                emails += [e]
                email_ids += [line]

    # this function returns TODO
    # to reject the submission, triggering an email notification

    print(f'new sub with {len(emails)} emails', file=sys.stderr)
    ret = new_sub(sub_id, user, timestamp, emails, email_ids)

    # we'll do something like this
    if ret is not None:
        with open(os.environ.get('VALID_LOG'), 'a') as valid_sub_log_file:
            print(log_msg, file=valid_sub_log_file)

    return ret

if __name__ == "__main__":
    main()
