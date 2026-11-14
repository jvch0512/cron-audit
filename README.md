# cron-audit

Cron is the oldest persistence trick in the book and it still works: one line in a crontab and an attacker survives reboots, password changes and half of your cleanup. cron-audit reads crontab files and flags the lines that look like persistence or abuse.

**Live demo:** https://jvch0512.github.io/cron-audit/ (a report on the synthetic crontabs in `examples/`)

Nim, standard library only, one static-friendly binary.

## Use

```bash
nim c -d:release -o:cron-audit src/cron_audit.nim      # or: make build
./cron-audit /etc/cron.d
./cron-audit /var/spool/cron/crontabs --html > report.html
./cron-audit /etc --fail-on critical                     # exit 1 in a pipeline
```

Point it at a file or a directory. Files under `cron.d`, `/etc/crontab` and anything with "system" in its name are read in system format (with the user column).

| Rule | Severity | What it catches |
|---|---|---|
| CR001 | critical | reverse shells: `/dev/tcp`, `nc -e`, `bash -i`, `mkfifo` |
| CR002 | critical | `curl ... \| bash` and similar download-and-run on a schedule |
| CR003 | critical | base64 or openssl-decoded payloads piped to a shell |
| CR004 | high | running from `/tmp`, `/dev/shm`, `/var/tmp` |
| CR006 | high | `@reboot` jobs that use network tools |
| CR007 | high | `LD_PRELOAD` and `chattr +i` tampering |
| CR009 | high | root jobs that chmod 777 or set setuid |
| CR005 | medium | hidden paths (`/.agent`) |
| CR008 | medium | every-minute jobs from unusual locations |
| CR010 | medium | detached `nohup` processes |

See [examples](examples) and [docs/sample-output.txt](docs/sample-output.txt).

## Limits

- Static review of schedule lines. It does not run anything and cannot see what a script does once called.
- Pattern based: a determined attacker can avoid these strings. It catches the common, careless cases, which are most of them.
- It does not cover systemd timers or `at` jobs.

## Where it fits

Linux compromise assessments, hardening reviews, incident response triage and a quick "is anything persisting?" check across a fleet.

## Tests

```bash
make test    # 17 unit tests
```

MIT.
