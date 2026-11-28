package approvalpage

import "html/template"

// The console's pages (console_pages.go), in the approval page's layout.

var consoleOverviewTmpl = template.Must(template.New("overview").Funcs(funcs).Parse(layout + `{{template "top" .}}
<div class="stats">
<a class="card" href="/console/servers"><div class="n">{{.Servers}}</div><div class="muted">servers</div></a>
<a class="card" href="/console/servers"><div class="n">{{.Instances}}</div><div class="muted">instances you manage</div></a>
<a class="card" href="/console/sessions"><div class="n">{{.Sessions}}</div><div class="muted">clients</div></a>
<a class="card" href="/console/tasks"><div class="n">{{.Tasks}}</div><div class="muted">running tasks</div></a>
<a class="card" href="/approvals/"><div class="n">{{.Pending}}</div><div class="muted">approvals for you</div></a>
</div>
<h2>Status</h2>
<div class="card"><dl>
<dt>Version</dt><dd>{{.Status.Version}}{{if .Status.RestartPending}} <b>(updated: restart the gateway)</b>{{end}}</dd>
{{if .Status.Replica}}<dt>Replica</dt><dd>{{.Status.Replica}} <span class="muted">(this page's; {{len .Status.Replicas}} live: {{join .Status.Replicas ", "}})</span></dd>{{end}}
<dt>Configuration</dt><dd>{{if .Status.ConfigError}}<b>the last change was refused</b>: {{.Status.ConfigError}}; the gateway runs with what it had{{else}}loaded{{end}} <span class="muted">({{.Status.ConfigReloads}} reloads since the start)</span></dd>
<dt>Server definitions</dt><dd>{{if .Status.ServersError}}<b>the last change was refused</b>: {{.Status.ServersError}}; the gateway serves the definitions it had{{else}}loaded{{end}}</dd>
{{if .Status.RestartNeeded}}<dt>Waiting for a restart</dt><dd>{{join .Status.RestartNeeded ", "}} <span class="muted">(take effect at the next start: roll the Deployment, or restart the service)</span></dd>{{end}}
<dt>Policy</dt><dd>{{.Policy.Mode}}{{range .Bundles}} · {{.}} {{index $.Policy.Bundles .}}{{end}}</dd>
</dl></div>
<p class="muted">The configuration is shown here, not edited: change it where it is kept (the ConfigMaps from Git, or the files in /etc/mcp-gateway on a host); the gateway reloads it and shows here whether it took it.</p>
{{template "bottom" .}}`))

var consoleServersTmpl = template.Must(template.New("servers").Funcs(funcs).Parse(layout + `{{template "top" .}}
{{range .List}}<div class="card"><div><b>{{.Name}}</b>{{if .Removed}} <span class="muted">(removed from the configuration; its instances stop once their calls are answered)</span>{{end}}</div>
{{if not .Removed}}<div class="muted">isolation {{.Isolation}} · network {{if .Network}}yes{{else}}no{{end}}{{if .SignIn}} · each user signs in{{end}}{{if .Landlock}} · Landlock{{end}}{{if .Privileged}} · privileged{{end}}{{if .Capabilities}} · capabilities {{join .Capabilities ", "}}{{end}}</div>{{end}}
{{if .Instances}}<table><tr><th>Instance</th><th>For</th><th>Started</th><th>Sessions</th><th>Definition</th><th></th></tr>
{{range .Instances}}<tr><td>{{.ID}}{{if .Replica}} <span class="muted">on {{.Replica}}</span>{{end}}</td><td>{{.Sub}}{{if .Issuer}} <span class="muted">({{.Issuer}})</span>{{end}}</td><td>{{ago .Started}}</td><td>{{.Sessions}}{{if .Busy}} · busy{{end}}</td><td>{{.Definition}}</td>
<td><form class="inline" method="post" action="/console/instances/{{.ID}}/stop"><input type="hidden" name="csrf" value="{{$.S.CSRF}}"><button class="danger">Stop</button></form></td></tr>
{{end}}</table>{{else}}<p class="muted">No instances you manage.</p>{{end}}</div>
{{else}}<p class="muted">No servers.</p>{{end}}
{{template "bottom" .}}`))

var consoleSessionsTmpl = template.Must(template.New("sessions").Funcs(funcs).Parse(layout + `{{template "top" .}}
{{if .List}}<table><tr><th>Client</th><th>For</th><th>Endpoint</th><th>Protocol</th><th>Since</th><th>Last active</th><th></th></tr>
{{range .List}}<tr><td>{{.Client.Name}} {{.Client.Version}}{{if .Replica}} <span class="muted">on {{.Replica}}</span>{{end}}</td><td>{{.Sub}}{{if .Issuer}} <span class="muted">({{.Issuer}})</span>{{end}}</td><td>{{.Endpoint}}</td><td>{{.Protocol}}{{if eq .Kind "agent"}} <span class="muted">(agent)</span>{{end}}</td>
<td>{{ago .Started}}</td><td>{{ago .LastActive}}</td>
<td><form class="inline" method="post" action="/console/sessions/{{.ID}}/end"><input type="hidden" name="csrf" value="{{$.S.CSRF}}"><button class="danger">End</button></form></td></tr>
{{end}}</table>{{else}}<p class="muted">No clients you manage are connected.</p>{{end}}
<h2>Ended in the last 24 hours</h2>
{{if .History}}<table><tr><th>Client</th><th>For</th><th>Endpoint</th><th>Calls</th><th>Ended</th><th>How</th></tr>
{{range .History}}<tr><td>{{.Client.Name}} {{.Client.Version}}</td><td>{{.Sub}}</td><td>{{.Endpoint}}</td><td>{{.Calls}}</td><td>{{ago .EndedAt}}</td><td>{{.End}}{{if .EndedBy}} <span class="muted">({{.EndedBy}})</span>{{end}}</td></tr>
{{end}}</table>{{else}}<p class="muted">None.</p>{{end}}
{{template "bottom" .}}`))

var consoleTasksTmpl = template.Must(template.New("tasks").Funcs(funcs).Parse(layout + `{{template "top" .}}
{{if .List}}<table><tr><th>Call</th><th>For</th><th>Status</th><th>Created</th><th>Updated</th><th></th></tr>
{{range .List}}<tr><td>{{.Server}}/{{.Tool}}{{if .Replica}} <span class="muted">on {{.Replica}}</span>{{end}}</td><td>{{.Sub}}</td><td>{{.Status}}{{if .Message}} <span class="muted">({{.Message}})</span>{{end}}</td><td>{{ago .Created}}</td><td>{{ago .Updated}}</td>
<td>{{if not .Ended}}<form class="inline" method="post" action="/console/tasks/{{.ID}}/cancel"><input type="hidden" name="csrf" value="{{$.S.CSRF}}"><button class="danger">Cancel</button></form>{{end}}</td></tr>
{{end}}</table>{{else}}<p class="muted">No tasks you manage.</p>{{end}}
{{template "bottom" .}}`))

var consoleSignInsTmpl = template.Must(template.New("signins").Funcs(funcs).Parse(layout + `{{template "top" .}}
<p class="muted">Principals' sign-ins to servers that need one (sign_in); the gateway keeps their tokens, never shown.</p>
{{if .List}}<table><tr><th>Server</th><th>Principal</th><th>Since</th><th>Expires</th><th>Renewable</th><th></th></tr>
{{range .List}}<tr><td>{{.Server}}</td><td>{{.Principal.Sub}}{{if .Principal.Issuer}} <span class="muted">({{.Principal.Issuer}})</span>{{end}}</td><td>{{ago .Since}}</td>
<td>{{if .Expiry.IsZero}}<span class="muted">not said</span>{{else}}{{clock .Expiry}}{{end}}</td><td>{{if .Refreshable}}yes{{else}}no{{end}}</td>
<td><form class="inline" method="post" action="/console/sign-ins/{{.Server}}/sign-out"><input type="hidden" name="csrf" value="{{$.S.CSRF}}">
<input type="hidden" name="principal" value="{{.Principal.Sub}}"><input type="hidden" name="transport" value="{{.Principal.Transport}}"><input type="hidden" name="iss" value="{{.Principal.Issuer}}">
<button class="danger">Sign out</button></form></td></tr>
{{end}}</table>{{else}}<p class="muted">No sign-ins you manage.</p>{{end}}
{{template "bottom" .}}`))

var consolePolicyTmpl = template.Must(template.New("policy").Funcs(funcs).Parse(layout + `{{template "top" .}}
<div class="card"><dl>
<dt>Mode</dt><dd>{{.Policy.Mode}}</dd>
{{range .Bundles}}<dt>{{.}}</dt><dd>revision {{index $.Policy.Bundles .}}</dd>{{end}}
</dl></div>
{{if .Roles}}<h2>Roles of server setups</h2>
<table><tr><th>Role</th><th>Setup</th><th>Description</th></tr>
{{range $r := .Roles}}{{with index $.Policy.ShippedRoles $r}}<tr><td>{{$r}}</td><td>{{.Setup}}</td><td>{{.Description}}</td></tr>{{end}}{{end}}</table>{{end}}
<h2>What if</h2>
<p class="muted">Paste proposed role data (data.json) to see the decisions it would change, before the change goes to Git. Nothing is changed here.</p>
<form method="post" action="/console/policy/whatif"><input type="hidden" name="csrf" value="{{.S.CSRF}}">
<textarea class="data" name="data" rows="12" spellcheck="false">{{.Data}}</textarea>
<div class="actions"><button>Show the changes</button></div></form>
{{if .WhatIfError}}<p class="note error">{{.WhatIfError}}</p>{{end}}
{{with .WhatIf}}<h2>Changes</h2>
<p class="muted">{{.Principals}} principals, {{.Resources}} tools, prompts and resources checked.</p>
{{if .Changes}}<table><tr><th>Principal</th><th>Server</th><th>What</th><th>Now</th><th>Then</th></tr>
{{range .Changes}}<tr><td>{{.Principal}}</td><td>{{.Server}}</td><td>{{.Kind}} {{.Name}}</td><td>{{.Before}}</td><td>{{.After}}</td></tr>
{{end}}</table>{{else}}<p>No decision would change.</p>{{end}}
{{if $.Unchecked}}<p class="muted">Not checked: {{range $.Unchecked}}{{.}} ({{index $.WhatIf.Unchecked .}}) {{end}}</p>{{end}}{{end}}
{{template "bottom" .}}`))

var consoleDoctorTmpl = template.Must(template.New("doctor").Funcs(funcs).Parse(layout + `{{template "top" .}}
{{if .DoctorError}}<p class="note error">{{.DoctorError}}</p>{{end}}
{{with .Report}}{{template "doctorReport" .}}
{{range .Replicas}}<h2>Replica {{.Replica}}</h2>{{if .Unreachable}}<p class="note error">It does not answer: {{.Unreachable}}</p>{{else}}{{template "doctorReport" .}}{{end}}
{{end}}{{end}}
{{if .Report}}<form method="post" action="/console/doctor"><input type="hidden" name="csrf" value="{{.S.CSRF}}"><div class="actions"><button>Check again</button></div></form>{{end}}
{{template "bottom" .}}
{{define "doctorReport"}}<p class="muted">Checked {{clock .Checked}} ({{if eq .Trigger "start"}}at the start{{else if eq .Trigger "reload"}}after a reload{{else}}on request{{end}}){{if .Replica}} by the replica {{.Replica}}{{end}}.</p>
<table><tr><th></th><th>Check</th><th>Result</th></tr>
{{range .Results}}<tr><td><span class="status {{.Status}}">{{.Status}}</span></td><td>{{.Check}}</td><td>{{.Summary}}{{range .Details}}<div class="muted">{{.}}</div>{{end}}</td></tr>
{{end}}</table>{{end}}`))
