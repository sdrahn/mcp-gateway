package approvalpage

import (
	"bytes"
	"html/template"
	"net/http"
	"strings"
	"time"
)

var funcs = template.FuncMap{
	"clock": func(t time.Time) string { return t.UTC().Format("2006-01-02 15:04:05 UTC") },
	"join":  strings.Join,
}

// style is the page's look, the Cockpit plugin's (cockpit/mcp-gateway/
// gateway.css): its palette, light and dark as the browser prefers (a
// test keeps the two palettes the same), its cards, tables and buttons.
const style = `
:root {
    --bg: #ffffff;
    --fg: #151515;
    --muted: #6a6e73;
    --card: #f5f5f5;
    --border: #d2d2d2;
    --accent: #0066cc;
    --accent-fg: #ffffff;
    --danger: #c9190b;
    --highlight: #fdf7e7;
    --error-bg: #faeae8;
    color-scheme: light dark;
}
@media (prefers-color-scheme: dark) {
    :root {
        --bg: #1b1d21;
        --fg: #e0e0e0;
        --muted: #a2a5a9;
        --card: #26292d;
        --border: #3c3f42;
        --accent: #73bcf7;
        --accent-fg: #151515;
        --danger: #fe5142;
        --highlight: #3d3419;
        --error-bg: #470000;
    }
}
body { margin: 0; background: var(--bg); color: var(--fg); font: 14px/1.5 "Red Hat Text", "RedHatText", system-ui, sans-serif; }
.masthead { display: flex; flex-wrap: wrap; align-items: center; gap: 0.5rem 1rem; padding: 0.6rem 1.5rem; background: var(--card); border-bottom: 1px solid var(--border); }
.masthead img { height: 2.25rem; width: auto; }
.masthead .product { font-size: 1.1rem; font-weight: 500; }
.masthead .who { margin-left: auto; display: flex; flex-wrap: wrap; align-items: center; gap: 0.5rem; }
main { max-width: 60rem; padding: 1rem 1.5rem; margin: 0 auto; }
h1 { font-size: 1.5rem; margin: 0 0 0.5rem; }
h2 { font-size: 1.15rem; margin: 1.5rem 0 0.25rem; }
a { color: var(--accent); }
.muted { color: var(--muted); }
.note { background: var(--highlight); border-left: 3px solid var(--accent); padding: 0.5rem 1rem; margin: 0.5rem 0; }
.card { background: var(--card); border: 1px solid var(--border); border-radius: 6px; padding: 0.75rem 1rem; margin: 0.75rem 0; }
.card dl { display: grid; grid-template-columns: max-content minmax(0, 1fr); gap: 0.1rem 1rem; margin: 0; }
.card dt { color: var(--muted); }
.card dd { margin: 0; overflow-wrap: anywhere; }
pre { margin: 0; white-space: pre-wrap; overflow-wrap: anywhere; font-size: 13px; max-height: 30em; overflow: auto; }
table { border-collapse: collapse; width: 100%; }
th, td { text-align: left; padding: 0.35rem 0.5rem; border-bottom: 1px solid var(--border); vertical-align: top; }
th { color: var(--muted); font-weight: normal; }
.actions { display: flex; flex-wrap: wrap; gap: 0.5rem; align-items: center; margin-top: 0.75rem; }
button, a.button { font: inherit; display: inline-block; padding: 0.3rem 0.9rem; border-radius: 4px; border: 1px solid var(--accent); background: var(--accent); color: var(--accent-fg); cursor: pointer; text-decoration: none; }
button.secondary { background: transparent; color: var(--accent); }
button.danger { border-color: var(--danger); background: transparent; color: var(--danger); }
form.inline { display: inline; margin: 0; }
fieldset { border: 0; padding: 0; margin: 0.75rem 0 0; }
label { margin-right: 1rem; }
@media (max-width: 600px) {
    .masthead, main { padding-left: 1rem; padding-right: 1rem; }
    table, tbody, tr, th, td { display: block; }
    tr:first-child { display: none; }
    tr { border-bottom: 1px solid var(--border); padding: 0.5rem 0; }
    td { border: 0; padding: 0.1rem 0; }
    .card dl { grid-template-columns: minmax(0, 1fr); }
    .card dt { margin-top: 0.25rem; }
}
`

const layout = `{{define "top"}}<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Title}} – MCP Gateway approvals</title>
{{if .B.Icon}}<link rel="icon" href="/approvals/static/favicon.ico">{{end}}
<style>` + style + `</style></head><body>
<header class="masthead">
{{if .B.Logo}}<img src="/approvals/static/logo.png" alt="">{{end}}
<div><div class="product">MCP Gateway approvals</div>
{{if .S}}{{if or .B.OSName .B.Host}}<div class="muted">{{.B.OSName}}{{if and .B.OSName .B.Host}} · {{end}}{{.B.Host}}</div>{{end}}{{end}}</div>
{{if .S}}<div class="who"><span>Signed in as <b>{{.S.Approver.Name}}</b>{{if .S.Approver.Groups}} <span class="muted">(groups {{join .S.Approver.Groups ", "}})</span>{{end}}</span>
<a href="/approvals/">Approvals</a>
<form class="inline" method="post" action="/approvals/logout"><input type="hidden" name="csrf" value="{{.S.CSRF}}"><button class="secondary">Sign out</button></form></div>{{end}}
</header>
<main>
<h1>{{.Title}}</h1>
{{end}}
{{define "bottom"}}</main></body></html>
{{end}}`

var pageTmpl = template.Must(template.New("page").Funcs(funcs).Parse(layout + `{{template "top" .}}<div class="card"><p>{{.Text}}</p>{{if .S}}<p><a href="/approvals/">Back to the approvals</a></p>{{end}}</div>{{template "bottom" .}}`))

var inboxTmpl = template.Must(template.New("inbox").Funcs(funcs).Parse(layout + `{{template "top" .}}
{{if .Msg}}<p class="note">Done: {{.Msg}}</p>{{end}}
<h2>Pending approvals</h2>
{{if .Pending}}<table><tr><th>Call</th><th>For</th><th>Client</th><th>Since</th><th>Open until</th><th></th></tr>
{{range .Pending}}<tr><td>{{.Server}}/{{.Name}}</td><td>{{.Principal.Sub}}</td><td>{{.Principal.Client.Name}} {{.Principal.Client.Version}}</td>
<td>{{clock .Created}}</td><td>{{clock .Expires}}</td><td><a class="button" href="/approvals/{{.ID}}">Decide</a></td></tr>
{{end}}</table>{{else}}<p class="muted">No approvals wait for you.</p>{{end}}
<h2>Grants</h2>
{{if .Grants}}<table><tr><th>Tool</th><th>For</th><th>Scope</th><th>Until</th><th>Approved by</th><th></th></tr>
{{range .Grants}}<tr><td>{{.Server}}/{{.Tool}}</td><td>{{.Sub}}</td><td>{{.Scope}}</td><td>{{.Expires}}</td><td>{{.ApprovedBy}}</td>
<td><form method="post" action="/approvals/grants/{{.ID}}/revoke"><input type="hidden" name="csrf" value="{{$.S.CSRF}}"><button class="danger">Revoke</button></form></td></tr>
{{end}}</table>{{else}}<p class="muted">No grants you may revoke.</p>{{end}}
{{template "bottom" .}}`))

var showTmpl = template.Must(template.New("show").Funcs(funcs).Parse(layout + `{{template "top" .}}
<div class="card"><dl>
<dt>Call</dt><dd>{{.P.Server}}/{{.P.Name}} ({{.P.Action}})</dd>
<dt>For</dt><dd>{{.P.Principal.Sub}}{{if .P.Principal.Issuer}} ({{.P.Principal.Issuer}}){{end}}</dd>
<dt>Client</dt><dd>{{.P.Principal.Client.Name}} {{.P.Principal.Client.Version}} <span class="muted">(as the agent names itself)</span></dd>
<dt>Since</dt><dd>{{clock .P.Created}}</dd>
<dt>Open until</dt><dd>{{clock .P.Expires}}</dd>
<dt>Waiting</dt><dd>{{if .P.Waiting}}yes, the call waits{{else}}no: the agent's next attempt finds the decision{{end}}</dd>
{{if .P.Prompt}}<dt>Request</dt><dd>{{.P.Prompt}}</dd>{{end}}
</dl></div>
<h2>Arguments</h2>
{{if .Args}}<div class="card"><pre>{{.Args}}</pre></div>{{else}}<p class="muted">Not shown (none, or the policy hides them).</p>{{end}}
<form method="post" action="/approvals/{{.P.ID}}">
<input type="hidden" name="csrf" value="{{.S.CSRF}}">
<fieldset><legend class="muted">Scope</legend>{{range $i, $s := .P.Scopes}}<label><input type="radio" name="scope" value="{{$s}}"{{if eq $i 0}} checked{{end}}> {{$s}}</label>{{end}}</fieldset>
<div class="actions"><button name="decision" value="approve">Approve</button><button class="danger" name="decision" value="deny">Deny</button></div>
</form>
{{template "bottom" .}}`))

// page shows a message.
func (pg *Page) page(w http.ResponseWriter, status int, title, text string, s *session) {
	pg.render(w, status, pageTmpl, map[string]any{"Text": text, "S": s, "Title": title})
}

// render executes t into a buffer first, so that a failure is an error
// page rather than half of one.
func (pg *Page) render(w http.ResponseWriter, status int, t *template.Template, data map[string]any) {
	data["B"] = pg.Branding
	if _, ok := data["Title"]; !ok {
		switch t {
		case inboxTmpl:
			data["Title"] = "Approvals"
		case showTmpl:
			data["Title"] = "Approve or deny"
		}
	}
	var b bytes.Buffer
	if err := t.Execute(&b, data); err != nil {
		pg.Log.Warn("approval page: rendering", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(b.Bytes())
}
