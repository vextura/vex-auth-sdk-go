// Package auth: OAuth2 wire-shape helpers.
//
// This file is HAND-WRITTEN (unlike client.go / types.go / operations.go /
// errors.go / doc.go which are generated). It adds three things codegen
// does not yet emit:
//
//  1. IssueTokenForm — POSTs application/x-www-form-urlencoded per RFC 6749
//     §3.2. vex-auth's token endpoint accepts both JSON (Vextura-internal
//     shape) and form-encoded (OAuth2 spec). Downstream OAuth2 clients
//     (vexctl refresh, vex-mcp-server auth) MUST use form-encoding to match
//     the spec and to keep vex-auth's r.ParseForm() path happy.
//  2. RevokeTokenForm + RevokeRequest — POSTs application/x-www-form-
//     urlencoded to /auth/revoke per RFC 7009 §2.1. Same rationale as
//     IssueTokenForm: form is the spec-mandated wire shape and vex-auth's
//     HandleRevoke reads r.FormValue("token"). Includes the RFC 7009 §2.2
//     no-info-leak semantics — 200 on unknown-token returns nil, never a
//     "not found" error.
//  3. OAuth2Error / decodeOAuth2ErrorOrFallback — RFC 6749 §5.2 error shape
//     ({error, error_description, error_uri}). The generated ErrorEnvelope
//     decoder only understands {code, message}, so actionable OAuth2 error
//     text is lost when vex-auth answers with the spec envelope.
//
// When vexctl clientgen learns the @httpFormRequest and OAuth2 error traits,
// this file should collapse into the generated output and be removed.

package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// OAuth2Error is the RFC 6749 §5.2 error response returned by /auth/token
// (and any other OAuth2 endpoint) when the request is rejected.
//
// Callers who need to branch on the OAuth2 code (e.g. surface
// "invalid_grant" to the user as "your refresh token expired, please log in
// again") should use IsOAuth2Error or errors.As with *OAuth2Error.
type OAuth2Error struct {
	// Code is one of the RFC 6749 §5.2 error codes: "invalid_request",
	// "invalid_client", "invalid_grant", "unauthorized_client",
	// "unsupported_grant_type", "invalid_scope", plus any extension codes
	// the server chooses to emit (e.g. "server_error").
	Code string
	// Description is the human-readable explanation (error_description).
	// May be empty when the server does not populate it.
	Description string
	// URI is an optional link to a page explaining the error (error_uri).
	// Rarely populated in practice.
	URI string
	// HTTPStatus is the originating HTTP status code (400/401/…). Preserved
	// for callers who care about the transport-level status.
	HTTPStatus int
}

// Error implements error. Format matches OAuth2 tooling conventions:
// "invalid_grant: refresh token has expired".
func (e *OAuth2Error) Error() string {
	if e == nil {
		return "oauth2: <nil>"
	}
	if e.Description != "" {
		return e.Code + ": " + e.Description
	}
	if e.Code != "" {
		return e.Code
	}
	return fmt.Sprintf("oauth2 error (http %d)", e.HTTPStatus)
}

// IsOAuth2Error extracts an *OAuth2Error from any error, if present.
// Returns (nil, false) when the error is not an OAuth2Error.
//
// Prefer this over a bare errors.As call at the call site — it keeps the
// idiom terse:
//
//	if oe, ok := auth.IsOAuth2Error(err); ok && oe.Code == "invalid_grant" {
//	    // prompt re-login
//	}
func IsOAuth2Error(err error) (*OAuth2Error, bool) {
	var oe *OAuth2Error
	if errors.As(err, &oe) {
		return oe, true
	}
	return nil, false
}

// decodeOAuth2ErrorOrFallback reads an error response body and returns the
// most specific error it can. Precedence:
//
//  1. RFC 6749 §5.2 OAuth2 envelope ({error, error_description, error_uri})
//     → returns *OAuth2Error.
//  2. Vextura internal envelope ({code, message, request_id, trace_id, …})
//     → returns ErrorEnvelope joined with the sentinel (same as
//     decodeError does today), so errors.Is(err, auth.ErrUnauthorized) and
//     errors.As(&auth.ErrorEnvelope{}) keep working.
//  3. Neither shape recognized → returns a raw "http N: <body>" error.
//
// The response body is consumed. Caller must not read it again.
func decodeOAuth2ErrorOrFallback(resp *http.Response) error {
	body, _ := io.ReadAll(resp.Body)

	// 1. Try the OAuth2 envelope first. "error" is the mandatory field per
	//    §5.2; if it's present and non-empty, treat the whole response as
	//    an OAuth2 error even if the server also included extra fields.
	var oe struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
		ErrorURI         string `json:"error_uri,omitempty"`
	}
	if err := json.Unmarshal(body, &oe); err == nil && oe.Error != "" {
		return &OAuth2Error{
			Code:        oe.Error,
			Description: oe.ErrorDescription,
			URI:         oe.ErrorURI,
			HTTPStatus:  resp.StatusCode,
		}
	}

	// 2. Fall back to the Vextura internal envelope. Reuse the same decode
	//    + sentinel-join logic as decodeError so behavior stays identical
	//    for callers that only understand the internal shape.
	var env ErrorEnvelope
	if err := json.Unmarshal(body, &env); err == nil && (env.Code != "" || env.Message != "") {
		env.Status = resp.StatusCode
		if sentinel := sentinelFor(env.Code, resp.StatusCode); sentinel != nil {
			return errors.Join(env, sentinel)
		}
		return env
	}

	// 3. Neither envelope. Surface raw text — bounded to something sensible
	//    so we don't dump megabytes into log output.
	preview := string(body)
	if len(preview) > 512 {
		preview = preview[:512] + "…"
	}
	return fmt.Errorf("http %d: %s", resp.StatusCode, preview)
}

// IssueTokenForm posts application/x-www-form-urlencoded to /auth/token per
// RFC 6749 §3.2. Prefer this over IssueToken for any OAuth2 grant flow
// (password, refresh_token, client_credentials, …); it matches the wire
// shape every OAuth2 spec-compliant server (including vex-auth) expects and
// unlocks the RFC 6749 §5.2 error decoder on failure.
//
// The JSON path (IssueToken) is retained for callers who want the internal
// Vextura envelope shape or need to send fields that don't fit the form
// encoding. Both methods share TokenRequest and TokenResponse.
//
// Encoding rules:
//   - Empty string fields are omitted (OAuth2 servers reject empty grant_type
//     etc. more clearly when the field is missing than when it's blank).
//   - Scope is joined with spaces per RFC 6749 §3.3.
//
// Errors are decoded through decodeOAuth2ErrorOrFallback so both OAuth2 and
// Vextura envelopes surface actionable information.
func (c *Client) IssueTokenForm(ctx context.Context, in TokenRequest) (TokenResponse, error) {
	var zero TokenResponse

	form := url.Values{}
	if in.GrantType != "" {
		form.Set("grant_type", in.GrantType)
	}
	if in.ClientId != "" {
		form.Set("client_id", in.ClientId)
	}
	if in.ClientSecret != "" {
		form.Set("client_secret", in.ClientSecret)
	}
	if in.Username != "" {
		form.Set("username", in.Username)
	}
	if in.Password != "" {
		form.Set("password", in.Password)
	}
	if in.RefreshToken != "" {
		form.Set("refresh_token", in.RefreshToken)
	}
	if in.Tenant != "" {
		form.Set("tenant", in.Tenant)
	}
	if len(in.Scope) > 0 {
		// RFC 6749 §3.3: scope is a space-separated list transported as a
		// single form field. Filter empty tokens defensively so a caller
		// passing []string{""} doesn't ship a stray space.
		joined := strings.Join(filterEmpty(in.Scope), " ")
		if joined != "" {
			form.Set("scope", joined)
		}
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.endpoint+"/auth/token", strings.NewReader(form.Encode()))
	if err != nil {
		return zero, fmt.Errorf("IssueTokenForm: new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return zero, fmt.Errorf("IssueTokenForm: http do: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return zero, decodeOAuth2ErrorOrFallback(resp)
	}
	if resp.StatusCode == http.StatusNoContent {
		return zero, nil
	}
	var out TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return zero, fmt.Errorf("IssueTokenForm: decode response: %w", err)
	}
	return out, nil
}

// RevokeRequest is the RFC 7009 §2.1 token revocation request.
//
// Unlike RevokeTokenRequest (the codegen struct which mirrors the internal
// Smithy shape), this type carries the optional client-authentication fields
// clients need when calling /auth/revoke as a public OAuth2 client. It stays
// hand-written for the same reason IssueTokenForm's inputs do — codegen
// does not yet emit the RFC 6749/7009 form-encoded shape.
type RevokeRequest struct {
	// Token is the credential to revoke. Required. Either an access token
	// or a refresh token — the server determines the type from the value
	// itself (with the optional TokenTypeHint helping short-circuit the
	// lookup per RFC 7009 §2.1).
	Token string
	// TokenTypeHint is one of "access_token" or "refresh_token" per RFC
	// 7009 §2.1. Optional; the server MUST still process the request when
	// the hint is missing or wrong. Empty means "no hint".
	TokenTypeHint string
	// ClientID identifies the OAuth2 client (RFC 6749 §2.3.1). Optional
	// when the client is already authenticated at the transport layer
	// (e.g. via Bearer on the SDK). Send it when acting as a public
	// client that has no other credentials.
	ClientID string
	// ClientSecret authenticates the client for confidential clients
	// (RFC 6749 §2.3.1). Optional. Empty for public clients.
	ClientSecret string
}

// RevokeTokenForm posts application/x-www-form-urlencoded to /auth/revoke
// per RFC 7009 §2.1. Prefer this over RevokeToken for any OAuth2 grant
// flow client (vexctl logout, vex-mcp-server auth-revoke, etc.) — it
// matches the spec wire shape every RFC 7009 server expects and unlocks
// the RFC 6749 §5.2 error decoder on failure.
//
// The JSON path (RevokeToken) is retained for backwards compatibility with
// callers on the internal Vextura envelope. Both target the same endpoint.
//
// Semantics (per RFC 7009 §2.2):
//   - 200 is returned whether the token was known or unknown. The server
//     MUST NOT distinguish, so this method returns nil in both cases.
//     Callers cannot use RevokeTokenForm to probe token validity.
//   - 400 invalid_request / 401 invalid_client → *OAuth2Error.
//   - 503 unsupported_token_type → *OAuth2Error per §2.2.1.
//
// Encoding rules mirror IssueTokenForm: empty fields are omitted so the
// server sees "missing" rather than "blank".
func (c *Client) RevokeTokenForm(ctx context.Context, in RevokeRequest) error {
	// Local validation — RFC 7009 §2.1 mandates the token parameter;
	// short-circuiting here avoids a pointless round-trip and gives the
	// caller an immediately-typed OAuth2Error rather than a server 400.
	if in.Token == "" {
		return &OAuth2Error{Code: "invalid_request", Description: "token is required"}
	}

	form := url.Values{}
	form.Set("token", in.Token)
	if in.TokenTypeHint != "" {
		form.Set("token_type_hint", in.TokenTypeHint)
	}
	if in.ClientID != "" {
		form.Set("client_id", in.ClientID)
	}
	if in.ClientSecret != "" {
		form.Set("client_secret", in.ClientSecret)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.endpoint+"/auth/revoke", strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("RevokeTokenForm: new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("RevokeTokenForm: http do: %w", err)
	}
	defer resp.Body.Close()

	// RFC 7009 §2.2: server MUST return 200 regardless of whether the token
	// was known. Do NOT branch on body content here — silently succeeding
	// on unknown-token is the spec-mandated behavior (no info leak).
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNoContent {
		return nil
	}
	return decodeOAuth2ErrorOrFallback(resp)
}

// filterEmpty drops empty strings from s without allocating when there are
// none. Used by IssueTokenForm to sanitize the scope slice.
func filterEmpty(s []string) []string {
	// Fast path: nothing to filter.
	empty := 0
	for _, v := range s {
		if v == "" {
			empty++
		}
	}
	if empty == 0 {
		return s
	}
	out := make([]string, 0, len(s)-empty)
	for _, v := range s {
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}
