package oauth

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"

	"github.com/sdrahn/mcp-gateway/internal/egress"
)

// maxBody bounds an answer of the server or the authorization server.
const maxBody = 1 << 20

// Do runs req with client (the helper's side): it makes the request(s)
// of the operation to the one host req names and checks the answers.
// credDir is $CREDENTIALS_DIRECTORY (the client secret, if any).
func Do(ctx context.Context, client *http.Client, req Request, credDir string) Response {
	if err := CheckURL(req.URL); err != nil {
		return failed(err)
	}
	var (
		r   Response
		err error
	)
	switch req.Op {
	case OpResource:
		r.Resource, err = resourceMetadata(ctx, client, req.URL)
	case OpServer:
		r.Server, err = serverMetadata(ctx, client, req.URL)
	case OpRegister:
		r.Client, err = register(ctx, client, req)
	case OpToken:
		r.Token, err = token(ctx, client, req, credDir)
	case OpRevoke:
		err = revoke(ctx, client, req, credDir)
	default:
		err = fmt.Errorf("unknown operation %q", req.Op)
	}
	if err != nil {
		return failed(err)
	}
	return r
}

func failed(err error) Response {
	var e *Error
	if errors.As(err, &e) {
		return Response{Error: e.Code, ErrorDescription: e.Description}
	}
	return Response{Error: HelperError, ErrorDescription: err.Error()}
}

// resourceMetadata finds the protected resource metadata of the MCP
// server at resource: the URL its 401 names (if on the same host, the
// only one the helper may reach), else the well-known URLs with and
// without the resource's path (RFC 9728, section 3.1).
func resourceMetadata(ctx context.Context, client *http.Client, resource string) (*ResourceMetadata, error) {
	var candidates []string
	if req, err := http.NewRequestWithContext(ctx, http.MethodGet, resource, nil); err == nil {
		req.Header.Set("Accept", "text/event-stream")
		if resp, err := client.Do(req); err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusUnauthorized {
				if m := authParam(resp.Header.Values("WWW-Authenticate"), "resource_metadata"); m != "" && SameOrigin(m, resource) {
					candidates = append(candidates, m)
				}
			}
		}
	}
	u, _ := url.Parse(resource)
	path := strings.TrimSuffix(u.EscapedPath(), "/")
	base := u.Scheme + "://" + u.Host + "/.well-known/oauth-protected-resource"
	if path != "" {
		candidates = append(candidates, base+path)
	}
	candidates = append(candidates, base)
	var last error
	for _, c := range candidates {
		var m ResourceMetadata
		if last = getJSON(ctx, client, c, &m); last != nil {
			continue
		}
		if strings.TrimSuffix(m.Resource, "/") != strings.TrimSuffix(resource, "/") {
			last = fmt.Errorf("%s names the resource %q, not %q", c, m.Resource, resource)
			continue
		}
		if len(m.AuthorizationServers) == 0 {
			return nil, fmt.Errorf("%s names no authorization server", c)
		}
		return &m, nil
	}
	return nil, fmt.Errorf("no protected resource metadata for %s: %w", resource, last)
}

// serverMetadata finds the metadata of the authorization server issuer:
// OAuth (RFC 8414) and OpenID Connect discovery, with the issuer's path
// inserted after the well-known part and, for OpenID Connect, appended.
func serverMetadata(ctx context.Context, client *http.Client, issuer string) (*ServerMetadata, error) {
	u, _ := url.Parse(issuer)
	path := strings.TrimSuffix(u.EscapedPath(), "/")
	origin := u.Scheme + "://" + u.Host
	candidates := []string{
		origin + "/.well-known/oauth-authorization-server" + path,
		origin + "/.well-known/openid-configuration" + path,
	}
	if path != "" {
		candidates = append(candidates, origin+path+"/.well-known/openid-configuration")
	}
	var last error
	for _, c := range candidates {
		var m ServerMetadata
		if last = getJSON(ctx, client, c, &m); last != nil {
			continue
		}
		if strings.TrimSuffix(m.Issuer, "/") != strings.TrimSuffix(issuer, "/") {
			last = fmt.Errorf("%s names the issuer %q, not %q", c, m.Issuer, issuer)
			continue
		}
		if err := m.Check(); err != nil {
			return nil, err
		}
		return &m, nil
	}
	return nil, fmt.Errorf("no authorization server metadata for %s: %w", issuer, last)
}

func register(ctx context.Context, client *http.Client, req Request) (*Client, error) {
	body, _ := json.Marshal(map[string]any{
		"client_name":                cmp.Or(req.ClientName, "mcp-gateway"),
		"redirect_uris":              []string{req.RedirectURI},
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": "none",
		"scope":                      req.Scope,
	})
	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, req.URL, strings.NewReader(string(body)))
	if err != nil {
		return nil, err
	}
	hreq.Header.Set("Content-Type", "application/json")
	var c Client
	if err := doJSON(client, hreq, &c); err != nil {
		return nil, err
	}
	if c.ClientID == "" {
		return nil, errors.New("the registration answer has no client_id")
	}
	return &c, nil
}

func token(ctx context.Context, client *http.Client, req Request, credDir string) (*Token, error) {
	form := url.Values{"grant_type": {req.GrantType}}
	switch req.GrantType {
	case "authorization_code":
		form.Set("code", req.Code)
		form.Set("code_verifier", req.CodeVerifier)
		form.Set("redirect_uri", req.RedirectURI)
	case "refresh_token":
		form.Set("refresh_token", req.RefreshToken)
		if req.Scope != "" {
			form.Set("scope", req.Scope)
		}
	default:
		return nil, fmt.Errorf("unknown grant type %q", req.GrantType)
	}
	if req.Resource != "" {
		form.Set("resource", req.Resource)
	}
	hreq, err := formRequest(ctx, req, form, credDir)
	if err != nil {
		return nil, err
	}
	var t Token
	if err := doJSON(client, hreq, &t); err != nil {
		return nil, err
	}
	if t.AccessToken == "" {
		return nil, errors.New("the token answer has no access_token")
	}
	if !strings.EqualFold(t.TokenType, "Bearer") {
		return nil, fmt.Errorf("token type %q, not Bearer", t.TokenType)
	}
	if strings.ContainsAny(t.AccessToken+t.RefreshToken, "\r\n") {
		return nil, errors.New("the token answer has a line break in a token")
	}
	return &t, nil
}

func revoke(ctx context.Context, client *http.Client, req Request, credDir string) error {
	form := url.Values{"token": {req.Token}}
	if req.TokenTypeHint != "" {
		form.Set("token_type_hint", req.TokenTypeHint)
	}
	hreq, err := formRequest(ctx, req, form, credDir)
	if err != nil {
		return err
	}
	resp, err := client.Do(hreq)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		return oauthError(resp)
	}
	return nil
}

// formRequest is a POST of form to req.URL as the client: with a secret,
// HTTP Basic authentication (client_secret_basic, RFC 6749 section
// 2.3.1), else client_id in the form (a public client).
func formRequest(ctx context.Context, req Request, form url.Values, credDir string) (*http.Request, error) {
	secret := req.ClientSecret
	if req.ClientSecretCredential != "" {
		s, err := egress.ReadCredential(credDir, req.ClientSecretCredential)
		if err != nil {
			return nil, err
		}
		secret = s
	}
	if secret == "" {
		form.Set("client_id", req.ClientID)
	}
	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, req.URL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	hreq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if secret != "" {
		hreq.SetBasicAuth(url.QueryEscape(req.ClientID), url.QueryEscape(secret))
	}
	return hreq, nil
}

func getJSON(ctx context.Context, client *http.Client, u string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	return doJSON(client, req, v)
}

// doJSON sends req and decodes a JSON answer into v; an error answer is
// returned as *Error if it is an OAuth one.
func doJSON(client *http.Client, req *http.Request, v any) error {
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		return oauthError(resp)
	}
	if mt, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type")); mt != "application/json" {
		return fmt.Errorf("%s: answer of type %q, not JSON", req.URL, mt)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return err
	}
	if len(body) > maxBody {
		return fmt.Errorf("%s: answer larger than %d bytes", req.URL, maxBody)
	}
	if err := json.Unmarshal(body, v); err != nil {
		return fmt.Errorf("%s: %w", req.URL, err)
	}
	return nil
}

func oauthError(resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	var e struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	if json.Unmarshal(body, &e) == nil && e.Error != "" {
		return &Error{Code: e.Error, Description: e.ErrorDescription}
	}
	return fmt.Errorf("%s: HTTP %s", resp.Request.URL, resp.Status)
}

// authParam returns the parameter name of a Bearer challenge in
// WWW-Authenticate values.
func authParam(values []string, name string) string {
	for _, v := range values {
		scheme, rest, _ := strings.Cut(strings.TrimSpace(v), " ")
		if !strings.EqualFold(scheme, "Bearer") {
			continue
		}
		for _, part := range splitParams(rest) {
			k, val, ok := strings.Cut(part, "=")
			if ok && strings.EqualFold(strings.TrimSpace(k), name) {
				return strings.Trim(strings.TrimSpace(val), `"`)
			}
		}
	}
	return ""
}

// splitParams splits auth-params at commas outside quoted strings.
func splitParams(s string) []string {
	var parts []string
	var cur strings.Builder
	quoted := false
	for _, r := range s {
		switch {
		case r == '"':
			quoted = !quoted
			cur.WriteRune(r)
		case r == ',' && !quoted:
			parts = append(parts, cur.String())
			cur.Reset()
		default:
			cur.WriteRune(r)
		}
	}
	return append(parts, cur.String())
}
