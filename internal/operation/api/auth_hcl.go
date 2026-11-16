package api

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"
)

// authMode identifies the on-disk auth block being edited. The API accepts the
// short names used by the UI; HCL uses the block names.
type authMode string

const (
	authModeBasic   authMode = "basic"
	authModeProtect authMode = "protect"
)

func parseAuthMode(raw string) (authMode, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case string(authModeBasic):
		return authModeBasic, nil
	case string(authModeProtect):
		return authModeProtect, nil
	default:
		return "", fmt.Errorf("mode must be %q or %q", authModeBasic, authModeProtect)
	}
}

func (m authMode) block() string {
	if m == authModeProtect {
		return "protect"
	}
	return "basic_auth"
}

// authConfigRequest is the editable subset of a route auth block. Pointer
// fields distinguish "leave unchanged" from an explicit empty value.
type authConfigRequest struct {
	Enabled    *bool   `json:"enabled"`
	Realm      *string `json:"realm"`
	Title      *string `json:"title"`
	SessionTTL *string `json:"session_ttl"`
	CookieName *string `json:"cookie_name"`
}

// mutateAuthSettings applies a settings-only change to one auth block. The
// users attribute is deliberately untouched: user CRUD has its own flow so a
// settings save can never erase credentials with a redacted/stale list.
//
// hclwrite is used so unmodified blocks, attributes, whitespace, and comments in
// the file survive byte-for-byte. Only the targeted block is mutated.
func mutateAuthSettings(src []byte, routePath string, mode authMode, req authConfigRequest) ([]byte, error) {
	return mutateAuthBlock(src, routePath, mode, func(body *hclwrite.Body) {
		if req.Enabled != nil {
			body.SetAttributeValue("enabled", cty.StringVal(toggleString(*req.Enabled)))
		}
		if mode == authModeBasic {
			setOptionalString(body, "realm", req.Realm)
			return
		}
		setOptionalString(body, "title", req.Title)
		setOptionalString(body, "session_ttl", req.SessionTTL)
		setOptionalString(body, "cookie_name", req.CookieName)
	})
}

// mutateAuthUsers updates the users list in one auth block. When the change is
// a pure append, value replacement, or single removal, the existing token
// stream is edited in place so comments attached to individual entries survive.
// A structural rewrite falls back to SetAttributeValue.
func mutateAuthUsers(src []byte, routePath string, mode authMode, users []string) ([]byte, error) {
	return mutateAuthBlock(src, routePath, mode, func(body *hclwrite.Body) {
		setAuthUserList(body, users)
	})
}

func mutateAuthBlock(src []byte, routePath string, mode authMode, apply func(*hclwrite.Body)) ([]byte, error) {
	file, diags := hclwrite.ParseConfig(src, "host.hcl", hcl.InitialPos)
	if diags.HasErrors() {
		return nil, fmt.Errorf("parse HCL: %s", diags.Error())
	}

	routeBlock := findRouteBlock(file.Body(), routePath)
	if routeBlock == nil {
		return nil, fmt.Errorf("route %q not found", routePath)
	}

	blockType := mode.block()
	authBlock := findNamedBlock(routeBlock.Body(), blockType)
	if authBlock == nil {
		// Keep a blank line before a newly-created block so the result reads
		// like a hand-written config rather than a dense token dump.
		routeBlock.Body().AppendNewline()
		authBlock = routeBlock.Body().AppendNewBlock(blockType, nil)
	}
	apply(authBlock.Body())
	return file.Bytes(), nil
}

func findRouteBlock(body *hclwrite.Body, routePath string) *hclwrite.Block {
	for _, block := range body.Blocks() {
		if block.Type() != "route" {
			continue
		}
		labels := block.Labels()
		if len(labels) == 1 && labels[0] == routePath {
			return block
		}
	}
	return nil
}

func findNamedBlock(body *hclwrite.Body, blockType string) *hclwrite.Block {
	for _, block := range body.Blocks() {
		if block.Type() == blockType {
			return block
		}
	}
	return nil
}

func setOptionalString(body *hclwrite.Body, name string, value *string) {
	if value == nil {
		return
	}
	trimmed := strings.TrimSpace(*value)
	if trimmed == "" {
		body.RemoveAttribute(name)
		return
	}
	body.SetAttributeValue(name, cty.StringVal(trimmed))
}

// setAuthUserList updates a route's users attribute. Most edits can be applied
// as token surgery, which keeps comments attached to individual entries; only
// structural surprises fall back to a full list rewrite.
func setAuthUserList(body *hclwrite.Body, users []string) {
	if len(users) == 0 {
		body.SetAttributeValue("users", cty.ListValEmpty(cty.String))
		return
	}

	attr := body.GetAttribute("users")
	if attr == nil || attr.Expr() == nil {
		body.SetAttributeValue("users", authUserListValue(users))
		return
	}

	tokens := attr.Expr().BuildTokens(nil)
	old, spans, ok := parseAuthListTokens(tokens)
	if !ok {
		body.SetAttributeValue("users", authUserListValue(users))
		return
	}

	switch {
	case len(users) == len(old)+1 && stringSlicesEqual(old, users[:len(old)]):
		out, ok := appendAuthUserTokens(tokens, spans, users[len(users)-1])
		if !ok {
			body.SetAttributeValue("users", authUserListValue(users))
			return
		}
		tokens = out
	case len(users) == len(old):
		out, ok := replaceAuthUserTokens(tokens, spans, old, users)
		if !ok {
			body.SetAttributeValue("users", authUserListValue(users))
			return
		}
		tokens = out
	case len(users) == len(old)-1:
		idx, ok := removedAuthUserIndex(old, users)
		if !ok {
			body.SetAttributeValue("users", authUserListValue(users))
			return
		}
		out, ok := deleteAuthUserTokens(tokens, spans, idx)
		if !ok {
			body.SetAttributeValue("users", authUserListValue(users))
			return
		}
		tokens = out
	default:
		body.SetAttributeValue("users", authUserListValue(users))
		return
	}

	body.SetAttributeRaw("users", tokens)
}

func authUserListValue(users []string) cty.Value {
	if len(users) == 0 {
		return cty.ListValEmpty(cty.String)
	}
	vals := make([]cty.Value, len(users))
	for i, u := range users {
		vals[i] = cty.StringVal(u)
	}
	return cty.ListVal(vals)
}

type authTokenSpan struct {
	start int
	end   int
}

// parseAuthListTokens returns the string values and their token spans for a
// literal list expression. Anything more complex (interpolation, variables) is
// rejected so the caller can fall back to a normal rewrite.
func parseAuthListTokens(tokens hclwrite.Tokens) ([]string, []authTokenSpan, bool) {
	if len(tokens) < 2 ||
		tokens[0].Type != hclsyntax.TokenOBrack ||
		tokens[len(tokens)-1].Type != hclsyntax.TokenCBrack {
		return nil, nil, false
	}

	var values []string
	var spans []authTokenSpan
	for i := 1; i < len(tokens)-1; i++ {
		switch tokens[i].Type {
		case hclsyntax.TokenComma, hclsyntax.TokenNewline, hclsyntax.TokenComment:
			continue
		case hclsyntax.TokenOQuote:
			start := i
			j := i + 1
			var raw []byte
			for j < len(tokens)-1 && tokens[j].Type != hclsyntax.TokenCQuote {
				if tokens[j].Type != hclsyntax.TokenQuotedLit {
					return nil, nil, false
				}
				raw = append(raw, tokens[j].Bytes...)
				j++
			}
			if j >= len(tokens)-1 {
				return nil, nil, false
			}
			value, err := strconv.Unquote(`"` + string(raw) + `"`)
			if err != nil {
				return nil, nil, false
			}
			values = append(values, value)
			spans = append(spans, authTokenSpan{start: start, end: j})
			i = j
		default:
			return nil, nil, false
		}
	}
	return values, spans, true
}

func appendAuthUserTokens(tokens hclwrite.Tokens, spans []authTokenSpan, value string) (hclwrite.Tokens, bool) {
	multi := tokensHaveNewline(tokens)
	valueTokens := hclwrite.TokensForValue(cty.StringVal(value))
	if len(valueTokens) == 0 {
		return nil, false
	}

	if len(spans) == 0 {
		insertAt := len(tokens) - 1 // before closing ]
		if !multi {
			valueTokens[0].SpacesBefore = 0
			return insertAuthTokens(tokens, insertAt, valueTokens), true
		}
		indent := tokens[len(tokens)-1].SpacesBefore + 2
		valueTokens[0].SpacesBefore = indent
		ins := hclwrite.Tokens{authNewlineToken()}
		ins = append(ins, valueTokens...)
		ins = append(ins, authNewlineToken())
		return insertAuthTokens(tokens, insertAt, ins), true
	}

	last := spans[len(spans)-1]
	insertAt := last.end + 1
	hasComma := insertAt < len(tokens) && tokens[insertAt].Type == hclsyntax.TokenComma
	if hasComma {
		insertAt++
	}
	indent := tokens[last.start].SpacesBefore

	var ins hclwrite.Tokens
	if multi {
		if hasComma {
			valueTokens[0].SpacesBefore = indent
			ins = hclwrite.Tokens{authNewlineToken()}
			ins = append(ins, valueTokens...)
			ins = append(ins, authCommaToken())
		} else {
			valueTokens[0].SpacesBefore = indent
			ins = hclwrite.Tokens{authCommaToken(), authNewlineToken()}
			ins = append(ins, valueTokens...)
		}
	} else {
		valueTokens[0].SpacesBefore = 1
		if hasComma {
			ins = append(hclwrite.Tokens{}, valueTokens...)
			ins = append(ins, authCommaToken())
		} else {
			ins = hclwrite.Tokens{authCommaToken()}
			ins = append(ins, valueTokens...)
		}
	}
	return insertAuthTokens(tokens, insertAt, ins), true
}

func replaceAuthUserTokens(tokens hclwrite.Tokens, spans []authTokenSpan, old, users []string) (hclwrite.Tokens, bool) {
	out := make(hclwrite.Tokens, 0, len(tokens))
	prev := 0
	for i, span := range spans {
		out = append(out, tokens[prev:span.start]...)
		if old[i] == users[i] {
			out = append(out, tokens[span.start:span.end+1]...)
		} else {
			valueTokens := hclwrite.TokensForValue(cty.StringVal(users[i]))
			if len(valueTokens) == 0 {
				return nil, false
			}
			valueTokens[0].SpacesBefore = tokens[span.start].SpacesBefore
			out = append(out, valueTokens...)
		}
		prev = span.end + 1
	}
	out = append(out, tokens[prev:]...)
	return out, true
}

func deleteAuthUserTokens(tokens hclwrite.Tokens, spans []authTokenSpan, idx int) (hclwrite.Tokens, bool) {
	// Single-line lists have no reliable comments to preserve and their
	// separator rules differ; let the caller rebuild instead.
	if !tokensHaveNewline(tokens) {
		return nil, false
	}

	span := spans[idx]
	start, end := span.start, span.end

	// Comments that start on their own line are labels for this entry.
	for start-1 > 0 &&
		tokens[start-1].Type == hclsyntax.TokenComment &&
		tokens[start-1].SpacesBefore > 1 {
		start--
	}

	hasTrailingComma := end+1 < len(tokens) && tokens[end+1].Type == hclsyntax.TokenComma
	if hasTrailingComma {
		end++
		// An inline comment after the comma belongs to the deleted entry.
		if end+1 < len(tokens) &&
			tokens[end+1].Type == hclsyntax.TokenComment &&
			tokens[end+1].SpacesBefore <= 1 {
			end++
		}
	} else {
		// Remove the separator before the entry instead.
		for p := start - 1; p >= 0; p-- {
			if tokens[p].Type == hclsyntax.TokenNewline {
				continue
			}
			if tokens[p].Type == hclsyntax.TokenComma {
				start = p
				break
			}
			break
		}
	}

	if end+1 < len(tokens) && tokens[end+1].Type == hclsyntax.TokenNewline {
		end++
	}

	out := make(hclwrite.Tokens, 0, len(tokens)-(end-start+1))
	out = append(out, tokens[:start]...)
	out = append(out, tokens[end+1:]...)
	return out, true
}

func removedAuthUserIndex(old, users []string) (int, bool) {
	idx := 0
	for idx < len(users) && old[idx] == users[idx] {
		idx++
	}
	if idx == len(users) {
		return len(old) - 1, true
	}
	if stringSlicesEqual(old[idx+1:], users[idx:]) {
		return idx, true
	}
	return 0, false
}

func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func tokensHaveNewline(tokens hclwrite.Tokens) bool {
	for _, tok := range tokens {
		if tok.Type == hclsyntax.TokenNewline {
			return true
		}
	}
	return false
}

func insertAuthTokens(tokens hclwrite.Tokens, at int, ins hclwrite.Tokens) hclwrite.Tokens {
	out := make(hclwrite.Tokens, 0, len(tokens)+len(ins))
	out = append(out, tokens[:at]...)
	out = append(out, ins...)
	out = append(out, tokens[at:]...)
	return out
}

func authNewlineToken() *hclwrite.Token {
	return &hclwrite.Token{Type: hclsyntax.TokenNewline, Bytes: []byte{'\n'}}
}

func authCommaToken() *hclwrite.Token {
	return &hclwrite.Token{Type: hclsyntax.TokenComma, Bytes: []byte{','}}
}

func toggleString(on bool) string {
	if on {
		return "on"
	}
	return "off"
}
