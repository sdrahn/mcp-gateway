# The channel an approval goes through (decision "ask"), in a file of its
# own beside authz.rego.
package mcp.authz

import rego.v1

# The channel an approval goes through: with several approvable
# permissions naming different channels, the strictest one, so that no
# permission's approval is weaker than it asks (oob: the agent's client
# sees nothing; url: it opens the page; form: it answers itself). An
# unknown channel counts as the strictest, and ties go by name: there is
# always exactly one, as one conflicting permission would otherwise fail
# the whole decision, and with it every tools/list.
channel_strictness := {"form": 0, "url": 1, "oob": 2}

ask_channels contains c if {
	some p in approvable
	c := object.get(p, "approval_channel", "url")
}

ask_channel := ranked[count(ranked) - 1][1] if {
	ranked := sort([[object.get(channel_strictness, c, 3), c] | some c in ask_channels])
	count(ranked) > 0
}
