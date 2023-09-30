# backups

Script and scheme to keep KDLP ORBIT production data storage redundant

## Current Status

Currently, we simply copy the user database into the repository with a unix timstamp suffix appended to the original filename. This is implmenented by the daily cronjob that invokes our `do_local_backup.sh`.

## Development Task List

- [x] create secure method to pull backups to external system (implemented using `cp -ar`, `tar pcf`, `tar xpf`, and of course, `scp`)
- [x] automate external backups (these are done by dev.underground.software like [this](https://www.youtube.com/watch?v=Epty_tmqR80))
- [ ] matrix data backup
- [ ] investigate which other data needs to be backed up.
