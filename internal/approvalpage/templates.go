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

const layout = `{{define "top"}}<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>{{.Title}} – MCP gateway approvals</title>
<style>
body{font-family:sans-serif;max-width:52em;margin:2em auto;padding:0 1em;line-height:1.5}
table{border-collapse:collapse;width:100%}td,th{text-align:left;padding:.3em .6em;border-bottom:1px solid #ccc;vertical-align:top}
pre{background:#f4f4f4;padding:.6em;overflow:auto;max-height:30em}
.who{color:#555;font-size:.9em}.msg{background:#e8f4e8;padding:.4em .8em}
button{padding:.3em 1em;margin-right:.5em}form.inline{display:inline}
</style></head><body>
{{if .S}}<p class="who">Signed in as <b>{{.S.Approver.Name}}</b>{{if .S.Approver.Groups}} (groups {{join .S.Approver.Groups ", "}}){{end}}
· <a href="/approvals/">Approvals</a>
<form class="inline" method="post" action="/approvals/logout"><input type="hidden" name="csrf" value="{{.S.CSRF}}"><button>Sign out</button></form></p>{{end}}
<h1>{{.Title}}</h1>
{{end}}
{{define "bottom"}}</body></html>
{{end}}`

var pageTmpl = template.Must(template.New("page").Funcs(funcs).Parse(layout + `{{template "top" .}}<p>{{.Text}}</p>{{if .S}}<p><a href="/approvals/">Back to the approvals</a></p>{{end}}{{template "bottom" .}}`))

var inboxTmpl = template.Must(template.New("inbox").Funcs(funcs).Parse(layout + `{{template "top" .}}
{{if .Msg}}<p class="msg">Done: {{.Msg}}</p>{{end}}
<h2>Pending approvals</h2>
{{if .Pending}}<table><tr><th>Call</th><th>For</th><th>Client</th><th>Since</th><th>Open until</th><th></th></tr>
{{range .Pending}}<tr><td>{{.Server}}/{{.Name}}</td><td>{{.Principal.Sub}}</td><td>{{.Principal.Client.Name}} {{.Principal.Client.Version}}</td>
<td>{{clock .Created}}</td><td>{{clock .Expires}}</td><td><a href="/approvals/{{.ID}}">Decide</a></td></tr>
{{end}}</table>{{else}}<p>No approvals wait for you.</p>{{end}}
<h2>Grants</h2>
{{if .Grants}}<table><tr><th>Tool</th><th>For</th><th>Scope</th><th>Until</th><th>Approved by</th><th></th></tr>
{{range .Grants}}<tr><td>{{.Server}}/{{.Tool}}</td><td>{{.Sub}}</td><td>{{.Scope}}</td><td>{{.Expires}}</td><td>{{.ApprovedBy}}</td>
<td><form method="post" action="/approvals/grants/{{.ID}}/revoke"><input type="hidden" name="csrf" value="{{$.S.CSRF}}"><button>Revoke</button></form></td></tr>
{{end}}</table>{{else}}<p>No grants you may revoke.</p>{{end}}
{{template "bottom" .}}`))

var showTmpl = template.Must(template.New("show").Funcs(funcs).Parse(layout + `{{template "top" .}}
<table>
<tr><th>Call</th><td>{{.P.Server}}/{{.P.Name}} ({{.P.Action}})</td></tr>
<tr><th>For</th><td>{{.P.Principal.Sub}}{{if .P.Principal.Issuer}} ({{.P.Principal.Issuer}}){{end}}</td></tr>
<tr><th>Client</th><td>{{.P.Principal.Client.Name}} {{.P.Principal.Client.Version}} <span class="who">(as the agent names itself)</span></td></tr>
<tr><th>Since</th><td>{{clock .P.Created}}</td></tr>
<tr><th>Open until</th><td>{{clock .P.Expires}}</td></tr>
<tr><th>Waiting</th><td>{{if .P.Waiting}}yes, the call waits{{else}}no: the agent's next attempt finds the decision{{end}}</td></tr>
{{if .P.Prompt}}<tr><th>Request</th><td>{{.P.Prompt}}</td></tr>{{end}}
</table>
<h2>Arguments</h2>
{{if .Args}}<pre>{{.Args}}</pre>{{else}}<p>Not shown (none, or the policy hides them).</p>{{end}}
<form method="post" action="/approvals/{{.P.ID}}">
<input type="hidden" name="csrf" value="{{.S.CSRF}}">
<p>Scope: {{range $i, $s := .P.Scopes}}<label><input type="radio" name="scope" value="{{$s}}"{{if eq $i 0}} checked{{end}}> {{$s}}</label> {{end}}</p>
<p><button name="decision" value="approve">Approve</button><button name="decision" value="deny">Deny</button></p>
</form>
{{template "bottom" .}}`))

// page shows a message.
func (pg *Page) page(w http.ResponseWriter, status int, title, text string, s *session) {
	pg.render(w, status, pageTmpl, map[string]any{"Text": text, "S": s, "Title": title})
}

// render executes t into a buffer first, so that a failure is an error
// page rather than half of one.
func (pg *Page) render(w http.ResponseWriter, status int, t *template.Template, data map[string]any) {
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
