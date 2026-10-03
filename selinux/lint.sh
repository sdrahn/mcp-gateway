#!/bin/sh
# Fails on an apostrophe in a comment inside an interface or template
# body of the policy's .if files. m4 ends the quoted body at it, silently dropping the
# rest of the interface; the module still builds.
status=0
for f in "${@:-$(dirname "$0")/mcp_gateway.if}"; do
	awk -v file="$f" '
		/^(interface|template)\(`/ { body = 1; next }
		body && /^'"'"')/ { body = 0; next }
		body && /^[[:space:]]*#/ && /'"'"'/ {
			printf "%s:%d: apostrophe inside an interface body: %s\n", file, NR, $0; bad = 1
		}
		END { exit bad }
	' "$f" || status=1
done
exit $status
