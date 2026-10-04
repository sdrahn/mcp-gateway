package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// A connector with -sign-in whose server refuses the access token (HTTP
// 401) asks the gateway for a new one: it writes a request of
// tokenMethod to stdout, with the refused token, and the gateway answers
// on stdin (it refreshes the token, or gives the one another instance
// got meanwhile). The request that met the 401 is sent again, once. If
// the gateway has none (the principal must sign in again), the connector
// ends with exitUnauthorized as before.
const (
	tokenMethod   = "mcp-gateway/token"
	tokenIDPrefix = "mcp-http-connector-token-"
	// tokenWait bounds waiting for the gateway's answer (it may refresh
	// the token through its helper).
	tokenWait = 150 * time.Second
)

// renewal is one request for a new token; requests that met a 401 with
// the same token wait for it.
type renewal struct {
	refused string
	done    chan struct{}
	ok      bool
}

// tokenAnswer is the gateway's answer to tokenMethod.
type tokenAnswer struct {
	ID     string `json:"id"`
	Result *struct {
		AccessToken string `json:"access_token"`
	} `json:"result"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
}

// bearer returns the access token the connector sends.
func (c *connector) bearer() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return strings.TrimPrefix(c.headers.Get("Authorization"), "Bearer ")
}

// renew gets a new access token from the gateway after the server refused
// refused, and reports whether the request may be sent again.
func (c *connector) renew(ctx context.Context, refused string) bool {
	c.tokMu.Lock()
	if r := c.renewing; r != nil && r.refused == refused {
		c.tokMu.Unlock()
		<-r.done
		return r.ok
	}
	if c.bearer() != refused {
		// Renewed since this request was sent.
		c.tokMu.Unlock()
		return true
	}
	r := &renewal{refused: refused, done: make(chan struct{})}
	c.renewing = r
	c.tokSeq++
	id := fmt.Sprintf("%s%d", tokenIDPrefix, c.tokSeq)
	answer := make(chan tokenAnswer, 1)
	c.tokWait = map[string]chan tokenAnswer{id: answer}
	c.tokMu.Unlock()

	defer func() {
		c.tokMu.Lock()
		c.renewing, c.tokWait = nil, nil
		c.tokMu.Unlock()
		close(r.done)
	}()
	req, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "method": tokenMethod,
		"params": map[string]string{"refused": refused}})
	c.write(req)
	select {
	case a := <-answer:
		if a.Error != nil || a.Result == nil || a.Result.AccessToken == "" {
			msg := "no token"
			if a.Error != nil {
				msg = a.Error.Message
			}
			c.log.Info("the gateway has no new access token", "err", msg)
			return false
		}
		c.mu.Lock()
		c.headers.Set("Authorization", "Bearer "+a.Result.AccessToken)
		c.mu.Unlock()
		c.log.Info("the server refused the access token; using a new one from the gateway")
		r.ok = true
		return true
	case <-time.After(tokenWait):
		c.log.Warn("the gateway did not answer the request for a new access token")
	case <-ctx.Done():
	case <-c.stopped:
	case <-c.stdinDone:
	}
	return false
}

// tokenReply takes line from stdin if it is the gateway's answer to a
// request for a new token.
func (c *connector) tokenReply(line []byte) bool {
	if !bytes.Contains(line, []byte(tokenIDPrefix)) {
		return false
	}
	var a tokenAnswer
	if json.Unmarshal(line, &a) != nil || !strings.HasPrefix(a.ID, tokenIDPrefix) {
		return false
	}
	c.tokMu.Lock()
	ch := c.tokWait[a.ID]
	c.tokMu.Unlock()
	if ch != nil {
		ch <- a
	}
	return true
}
