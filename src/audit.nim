## cron-audit: finds persistence and abuse in crontab files. Nim stdlib only.
import std/[strutils, os, algorithm]

type
  Severity* = enum sevInfo = "info", sevMedium = "medium", sevHigh = "high", sevCritical = "critical"
  Finding* = object
    file*: string
    line*: int
    rule*: string
    severity*: Severity
    message*: string
    cmd*: string

proc has(s: string, subs: varargs[string]): bool =
  for x in subs:
    if x in s: return true

proc splitJob(line: string, systemFormat: bool): tuple[sched, user, cmd: string] =
  ## "m h dom mon dow [user] cmd" or "@reboot [user] cmd"
  let parts = line.splitWhitespace()
  var idx = 0
  if parts.len == 0: return
  if parts[0].startsWith("@"):
    result.sched = parts[0]; idx = 1
  else:
    if parts.len < 6: return
    result.sched = parts[0 .. 4].join(" "); idx = 5
  if systemFormat and idx < parts.len:
    result.user = parts[idx]; inc idx
  if idx < parts.len: result.cmd = parts[idx .. ^1].join(" ")

proc audit*(text, file: string, systemFormat = false): seq[Finding] =
  var n = 0
  for raw in text.splitLines():
    inc n
    let line = raw.strip()
    if line.len == 0 or line.startsWith("#"): continue
    if '=' in line.split(' ')[0] and not line.startsWith("@") and not line[0].isDigit and line[0] != '*': continue  # VAR=value
    let (sched, user, cmd) = splitJob(line, systemFormat)
    if cmd.len == 0: continue
    let lc = cmd.toLowerAscii()
    template add(r: string, sev: Severity, msg: string) =
      result.add Finding(file: file, line: n, rule: r, severity: sev, message: msg, cmd: cmd[0 .. min(cmd.high, 110)])
    if lc.has("/dev/tcp/", "/dev/udp/", "nc -e", "ncat -e", "bash -i", "sh -i >&", "socat exec", "mkfifo"):
      add("CR001", sevCritical, "reverse shell pattern")
    if (lc.has("curl ", "wget ", "fetch ")) and lc.has("| sh", "|sh", "| bash", "|bash", "| python", "| perl"):
      add("CR002", sevCritical, "downloads and executes remote code on a schedule")
    if lc.has("base64 -d", "base64 --decode", "openssl enc -d") and lc.has("| sh", "|sh", "| bash", "|bash", "eval"):
      add("CR003", sevCritical, "decodes a hidden payload and runs it")
    if lc.has("/tmp/", "/dev/shm/", "/var/tmp/") :
      add("CR004", sevHigh, "runs something from a world-writable directory")
    if lc.has("/.") and not lc.has("/.local/bin", "/.config/"):
      add("CR005", sevMedium, "runs from a hidden path")
    if sched == "@reboot" and lc.has("curl", "wget", "nc ", "ncat", "python -c", "perl -e"):
      add("CR006", sevHigh, "@reboot job that uses network tools: classic persistence")
    if lc.has("ld_preload", "chattr +i", "chattr +a"):
      add("CR007", sevHigh, "rootkit-style tampering (LD_PRELOAD or immutable flags)")
    if sched == "* * * * *" and not lc.startsWith("/usr/") and not lc.startsWith("/opt/") and not lc.startsWith("/etc/"):
      add("CR008", sevMedium, "runs every minute from an unusual location")
    if systemFormat and user == "root" and lc.has("chmod 777", "chmod +s", "chmod u+s"):
      add("CR009", sevHigh, "root job that opens permissions or sets setuid")
    if lc.has("2>&1 | mail", "> /dev/null 2>&1 &") and lc.has("nohup"):
      add("CR010", sevMedium, "detached background process hidden from output")

proc auditPath*(path: string): seq[Finding] =
  var files: seq[string]
  if dirExists(path):
    for f in walkDirRec(path): files.add f
    files.sort()
  else:
    files.add path
  for f in files:
    let sys = "/cron.d/" in f or f.endsWith("/etc/crontab") or "system" in extractFilename(f)
    result.add audit(readFile(f), f.relativePath(if dirExists(path): path else: parentDir(path)), sys)
  result.sort(proc(a, b: Finding): int =
    if a.severity != b.severity: return cmp(b.severity.ord, a.severity.ord)
    if a.file != b.file: return cmp(a.file, b.file)
    cmp(a.line, b.line))

proc renderText*(fs: seq[Finding]): string =
  result = $fs.len & " findings\n"
  for f in fs:
    result.add alignLeft(($f.severity).toUpperAscii(), 9) & f.rule & " " & f.file & ":" & $f.line & "\n         " & f.message & "\n         " & f.cmd & "\n"

proc esc(s: string): string =
  s.multiReplace(("&", "&amp;"), ("<", "&lt;"), (">", "&gt;"), ("\"", "&quot;"))

proc renderHtml*(fs: seq[Finding]): string =
  var rows = ""
  for f in fs:
    rows.add "<tr><td class=\"" & $f.severity & "\">" & $f.severity & "</td><td>" & f.rule & "</td><td>" & esc(f.file) & ":" & $f.line & "</td><td>" & esc(f.message) & "<br><code>" & esc(f.cmd) & "</code></td></tr>"
  """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'"><title>cron-audit</title><style>:root{color-scheme:dark}body{margin:0;padding:28px;background:#0e1319;color:#e8eef5;font:14px/1.5 system-ui,sans-serif}h1{margin:0 0 4px}.sub{color:#8b98a8}table{border-collapse:collapse;width:100%;margin-top:14px}th,td{text-align:left;padding:8px 10px;border-bottom:1px solid #2a3441;vertical-align:top}th{color:#8b98a8}.critical{color:#f85149;font-weight:700}.high{color:#f0883e;font-weight:700}.medium{color:#e3b341;font-weight:700}code{color:#7ee787;word-break:break-all}</style></head><body><h1>cron-audit</h1><p class="sub">Persistence hunter for crontab files. Nim, standard library only. Synthetic crontabs, """ & $fs.len & """ findings.</p><table><tr><th>Severity</th><th>Rule</th><th>Where</th><th>What</th></tr>""" & rows & """</table><p class="sub">Static review of schedule lines. It does not run anything and cannot see what a script does.</p></body></html>
"""
