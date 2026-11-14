build:
	nim c -d:release --hints:off -o:cron-audit src/cron_audit.nim

test:
	nim c -r --hints:off -d:release -o:tests/t_audit tests/t_audit.nim

sample: build
	./cron-audit examples > docs/sample-output.txt
	./cron-audit examples --html > site/index.html
