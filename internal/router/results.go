package router

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"unicode/utf8"

	"github.com/sdrahn/mcp-gateway/internal/jsonrpc"
	"github.com/sdrahn/mcp-gateway/internal/pep"
)

// maxResultError bounds the error text of an mcp-result audit record.
const maxResultError = 200

// callOutcome is the outcome of a forwarded call for its mcp-result
// audit record, and a short error text: "ok"; "tool_error" with the
// result's first text (isError); "cancelled" or "timeout" when the
// call's context ended; else "error" with the JSON-RPC error's message.
// sendErr is the error of the request to the server, if any.
func callOutcome(ctx context.Context, raw json.RawMessage, rerr *jsonrpc.Error, sendErr error) (string, string) {
	if rerr != nil || sendErr != nil {
		switch {
		case errors.Is(sendErr, context.Canceled) || errors.Is(ctx.Err(), context.Canceled):
			return "cancelled", ""
		case errors.Is(sendErr, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded):
			return "timeout", ""
		}
		msg := ""
		if rerr != nil {
			msg = rerr.Message
		} else {
			msg = sendErr.Error()
		}
		return "error", shortText(msg)
	}
	var res struct {
		IsError bool `json:"isError"`
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	if json.Unmarshal(raw, &res) != nil || !res.IsError {
		return "ok", ""
	}
	for _, c := range res.Content {
		if c.Type == "text" && c.Text != "" {
			return "tool_error", shortText(c.Text)
		}
	}
	return "tool_error", ""
}

// shortText is s on one line, cut to maxResultError bytes (at a rune).
func shortText(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) <= maxResultError {
		return s
	}
	cut := maxResultError
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…"
}

// tokenText is a progress token as text: a string token without its
// quotes, a number as it was sent.
func tokenText(token json.RawMessage) string {
	var str string
	if json.Unmarshal(token, &str) == nil {
		return str
	}
	return string(token)
}

// storedGrant is the stored grant that allowed a call, for its audit
// records: policy allowed it "approved" (the bundled policy's reason for
// an allow by a grant) with the principal's grants for the tool, which
// the store matched on the principal, session and expiry. The policy does
// not say which one it used if there are several: the first.
func storedGrant(dec pep.Decision, in pep.Input) *pep.Grant {
	if dec.Effect != pep.Allow || dec.Reason != "approved" || len(in.Grants) == 0 {
		return nil
	}
	return &in.Grants[0]
}
