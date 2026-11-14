import std/[os, strutils]
import audit

const usage = "usage: cron-audit <crontab file or directory> [--html] [--fail-on high|critical]\nExit: 0 ok, 1 findings at or above --fail-on, 2 bad input.\n"

proc main(): int =
  let args = commandLineParams()
  if args.len == 0 or args[0].startsWith("--"): stderr.write usage; return 2
  var html = false
  var failOn = ""
  var i = 1
  while i < args.len:
    case args[i]
    of "--html": html = true
    of "--fail-on":
      if i + 1 >= args.len or args[i + 1] notin ["high", "critical"]: stderr.write "error: --fail-on needs high or critical\n"; return 2
      failOn = args[i + 1]; inc i
    else: stderr.write "error: unknown option " & args[i] & "\n" & usage; return 2
    inc i
  if not fileExists(args[0]) and not dirExists(args[0]): stderr.write "error: no such file or directory: " & args[0] & "\n"; return 2
  let fs = try: auditPath(args[0]) except IOError, OSError: (stderr.write "error: " & getCurrentExceptionMsg() & "\n"; return 2)
  stdout.write (if html: renderHtml(fs) else: renderText(fs))
  if failOn != "":
    let floor = if failOn == "critical": sevCritical else: sevHigh
    for f in fs:
      if f.severity >= floor: return 1
  0

quit main()
