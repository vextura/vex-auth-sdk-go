package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// -------- IssueTokenForm: encoding coverage --------

// Every string field on TokenRequest must round-trip through the form encoder.
// Scope ([]string) is a special case: it must be space-joined per RFC 6749 §3.3.
func TestIssueTokenForm_EncodesAllFields(t *testing.T) {
	t.Parallel()

	var gotForm url.Values
	var gotCT, gotAccept, gotAuth string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/auth/token" {
			t.Errorf("wrong path: %s", r.URL.Path)
		}
		if r.Method != "POST" {
			t.Errorf("wrong method: %s", r.Method)
		}
		gotCT = r.Header.Get("Content-Type")
		gotAccept = r.Header.Get("Accept")
		gotAuth = r.Header.Get("Authorization")
		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm: %v", err)
		}
		gotForm = r.PostForm
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(TokenResponse{
			AccessToken:  "AT",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
			RefreshToken: "RT",
		})
	}))
	defer srv.Close()

	c := New(srv.URL, "adminBearer")
	out, err := c.IssueTokenForm(context.Background(), TokenRequest{
		GrantType:    "password",
		ClientId:     "cid",
		ClientSecret: "csecret",
		Username:     "alice",
		Password:     "p4ss w0rd", // spaces + non-ASCII edge case
		RefreshToken: "old-rt",
		Tenant:       "acme",
		Scope:        []string{"read", "write", ""},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.AccessToken != "AT" || out.RefreshToken != "RT" {
		t.Errorf("response not decoded: %+v", out)
	}

	if gotCT != "application/x-www-form-urlencoded" {
		t.Errorf("Content-Type = %q, want application/x-www-form-urlencoded", gotCT)
	}
	if gotAccept != "application/json" {
		t.Errorf("Accept = %q, want application/json", gotAccept)
	}
	if gotAuth != "Bearer adminBearer" {
		t.Errorf("Authorization = %q, want Bearer adminBearer", gotAuth)
	}

	want := map[string]string{
		"grant_type":    "password",
		"client_id":     "cid",
		"client_secret": "csecret",
		"username":      "alice",
		"password":      "p4ss w0rd",
		"refresh_token": "old-rt",
		"tenant":        "acme",
		"scope":         "read write", // space-joined per §3.3, empty token dropped
	}
	for k, v := range want {
		if got := gotForm.Get(k); got != v {
			t.Errorf("form[%s] = %q, want %q", k, got, v)
		}
	}
	if len(gotForm) != len(want) {
		t.Errorf("unexpected extra fields: got %d keys (%v), want %d", len(gotForm), keys(gotForm), len(want))
	}
}

// Empty string fields must be omitted from the form entirely (not sent as
// key=). This matters because vex-auth (and other OAuth2 servers) validate
// each present field; a blank grant_type produces "invalid_request" rather
// than the desired "missing grant_type".
func TestIssueTokenForm_OmitsEmptyFields(t *testing.T) {
	t.Parallel()

	var gotForm url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotForm = r.PostForm
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(TokenResponse{AccessToken: "AT"})
	}))
	defer srv.Close()

	c := New(srv.URL, "") // no bearer either
	_, err := c.IssueTokenForm(context.Background(), TokenRequest{
		GrantType:    "refresh_token",
		RefreshToken: "rt",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, present := gotForm["client_id"]; present {
		t.Errorf("client_id should be omitted when empty, got form=%v", gotForm)
	}
	if _, present := gotForm["scope"]; present {
		t.Errorf("scope should be omitted when nil, got form=%v", gotForm)
	}
	if gotForm.Get("grant_type") != "refresh_token" || gotForm.Get("refresh_token") != "rt" {
		t.Errorf("required fields missing: %v", gotForm)
	}
}

// Scope containing only empty strings must not emit a stray "scope=" field.
func TestIssueTokenForm_ScopeAllEmpty(t *testing.T) {
	t.Parallel()

	var gotForm url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotForm = r.PostForm
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(TokenResponse{AccessToken: "AT"})
	}))
	defer srv.Close()

	c := New(srv.URL, "")
	_, err := c.IssueTokenForm(context.Background(), TokenRequest{
		GrantType: "refresh_token",
		Scope:     []string{"", ""},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, present := gotForm["scope"]; present {
		t.Errorf("scope should be omitted when all elements empty, got %v", gotForm)
	}
}

// -------- OAuth2 error decoding: every RFC 6749 §5.2 code --------

func TestIssueTokenForm_OAuth2Errors(t *testing.T) {
	t.Parallel()

	codes := []struct {
		code   string
		status int
		desc   string
	}{
		{"invalid_request", http.StatusBadRequest, "missing grant_type"},
		{"invalid_client", http.StatusUnauthorized, "unknown client"},
		{"invalid_grant", http.StatusBadRequest, "refresh token expired"},
		{"unauthorized_client", http.StatusBadRequest, "client not allowed for this grant"},
		{"unsupported_grant_type", http.StatusBadRequest, "grant_type not supported"},
		{"invalid_scope", http.StatusBadRequest, "scope out of bounds"},
	}
	for _, tc := range codes {
		tc := tc
		t.Run(tc.code, func(t *testing.T) {
			t.Parallel()
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				_, _ = fmt.Fprintf(w, `{"error":%q,"error_description":%q}`, tc.code, tc.desc)
			}))
			defer srv.Close()

			c := New(srv.URL, "")
			_, err := c.IssueTokenForm(context.Background(), TokenRequest{GrantType: "refresh_token"})
			if err == nil {
				t.Fatalf("want error, got nil")
			}
			oe, ok := IsOAuth2Error(err)
			if !ok {
				t.Fatalf("IsOAuth2Error(err)=false, err=%v (%T)", err, err)
			}
			if oe.Code != tc.code {
				t.Errorf("Code=%q, want %q", oe.Code, tc.code)
			}
			if oe.Description != tc.desc {
				t.Errorf("Description=%q, want %q", oe.Description, tc.desc)
			}
			if oe.HTTPStatus != tc.status {
				t.Errorf("HTTPStatus=%d, want %d", oe.HTTPStatus, tc.status)
			}
			wantMsg := tc.code + ": " + tc.desc
			if oe.Error() != wantMsg {
				t.Errorf("Error()=%q, want %q", oe.Error(), wantMsg)
			}
		})
	}
}

// error_uri is optional per §5.2 — round-trip when present.
func TestIssueTokenForm_OAuth2Error_URI(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"error":"invalid_grant","error_description":"expired","error_uri":"https://docs.example.com/e/invalid_grant"}`)
	}))
	defer srv.Close()

	c := New(srv.URL, "")
	_, err := c.IssueTokenForm(context.Background(), TokenRequest{GrantType: "refresh_token"})
	oe, ok := IsOAuth2Error(err)
	if !ok {
		t.Fatalf("IsOAuth2Error=false, err=%v", err)
	}
	if oe.URI != "https://docs.example.com/e/invalid_grant" {
		t.Errorf("URI=%q, want https://docs.example.com/e/invalid_grant", oe.URI)
	}
}

// Error() falls back to just the code when description is empty, and to a
// http-status stub when everything is empty. Belt-and-suspenders coverage
// for the format branches.
func TestOAuth2Error_ErrorFormat(t *testing.T) {
	t.Parallel()
	if (&OAuth2Error{Code: "x"}).Error() != "x" {
		t.Errorf("Code-only format wrong")
	}
	if !strings.Contains((&OAuth2Error{HTTPStatus: 500}).Error(), "500") {
		t.Errorf("empty-fields format should mention status")
	}
	if (*OAuth2Error)(nil).Error() != "oauth2: <nil>" {
		t.Errorf("nil receiver should not panic")
	}
}

// errors.As round-trip: OAuth2Error must be reachable through errors.As even
// when wrapped by fmt.Errorf. Confirms IsOAuth2Error works through wrappers.
func TestIsOAuth2Error_Wrapped(t *testing.T) {
	t.Parallel()
	inner := &OAuth2Error{Code: "invalid_grant", HTTPStatus: 400}
	wrapped := fmt.Errorf("refresh failed: %w", inner)

	oe, ok := IsOAuth2Error(wrapped)
	if !ok || oe.Code != "invalid_grant" {
		t.Errorf("wrapped extract failed: ok=%v oe=%+v", ok, oe)
	}

	// Also verify plain errors.As path (no wrapper).
	var direct *OAuth2Error
	if !errors.As(inner, &direct) || direct != inner {
		t.Errorf("errors.As direct path broken")
	}

	// Non-OAuth2 error must return (nil, false).
	if oe, ok := IsOAuth2Error(errors.New("plain")); ok || oe != nil {
		t.Errorf("false-positive on plain error: ok=%v oe=%+v", ok, oe)
	}
	// Nil is a valid input.
	if oe, ok := IsOAuth2Error(nil); ok || oe != nil {
		t.Errorf("IsOAuth2Error(nil) should return (nil,false), got (%+v, %v)", oe, ok)
	}
}

// -------- Fallback envelopes --------

// When the body isn't OAuth2 but IS Vextura internal envelope, we must
// return an ErrorEnvelope joined with the sentinel — same behavior as
// decodeError. This is what keeps existing errors.Is(err, ErrUnauthorized)
// callers working.
func TestIssueTokenForm_VexturaEnvelopeFallback(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"code":"UNAUTHORIZED","message":"bad token","request_id":"req-1","trace_id":"trc-1"}`)
	}))
	defer srv.Close()

	c := New(srv.URL, "")
	_, err := c.IssueTokenForm(context.Background(), TokenRequest{GrantType: "refresh_token"})
	if err == nil {
		t.Fatal("want error")
	}
	if _, ok := IsOAuth2Error(err); ok {
		t.Errorf("must NOT be classified as OAuth2Error, err=%v", err)
	}
	if !errors.Is(err, ErrUnauthorized) {
		t.Errorf("errors.Is(err, ErrUnauthorized) false, err=%v", err)
	}
	var env ErrorEnvelope
	if !errors.As(err, &env) {
		t.Fatalf("errors.As envelope failed, err=%v", err)
	}
	if env.Code != "UNAUTHORIZED" || env.Message != "bad token" || env.Status != 401 || env.RequestID != "req-1" {
		t.Errorf("envelope not fully decoded: %+v", env)
	}
}

// When neither envelope is present, surface the raw body with the HTTP
// status. Prevents "unknown error" swallowing.
func TestIssueTokenForm_RawBodyFallback(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = io.WriteString(w, "upstream nginx: connection refused")
	}))
	defer srv.Close()

	c := New(srv.URL, "")
	_, err := c.IssueTokenForm(context.Background(), TokenRequest{GrantType: "refresh_token"})
	if err == nil {
		t.Fatal("want error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "502") || !strings.Contains(msg, "connection refused") {
		t.Errorf("raw-body error missing detail: %q", msg)
	}
	if _, ok := IsOAuth2Error(err); ok {
		t.Errorf("raw body should not classify as OAuth2Error")
	}
}

// Very large raw bodies must be truncated so a broken upstream can't dump
// megabytes into the caller's log stream.
func TestIssueTokenForm_RawBodyTruncated(t *testing.T) {
	t.Parallel()
	big := strings.Repeat("x", 4096)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, big)
	}))
	defer srv.Close()

	c := New(srv.URL, "")
	_, err := c.IssueTokenForm(context.Background(), TokenRequest{GrantType: "refresh_token"})
	if err == nil {
		t.Fatal("want error")
	}
	if len(err.Error()) > 700 { // 512 preview + "http 500: " + ellipsis
		t.Errorf("body not truncated, len=%d", len(err.Error()))
	}
}

// -------- IssueToken (JSON path) now routes through the same decoder --------

// The task requires the JSON IssueToken to also surface OAuth2 errors. This
// guards against regressions where a codegen re-run reverts to decodeError.
func TestIssueToken_JSONPath_DecodesOAuth2Error(t *testing.T) {
	t.Parallel()
	var gotCT string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCT = r.Header.Get("Content-Type")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"error":"invalid_grant","error_description":"refresh token expired"}`)
	}))
	defer srv.Close()

	c := New(srv.URL, "")
	_, err := c.IssueToken(context.Background(), TokenRequest{
		GrantType:    "refresh_token",
		RefreshToken: "rt",
	})
	if err == nil {
		t.Fatal("want error")
	}
	if gotCT != "application/json" {
		t.Errorf("JSON path Content-Type=%q, want application/json", gotCT)
	}
	oe, ok := IsOAuth2Error(err)
	if !ok || oe.Code != "invalid_grant" {
		t.Errorf("JSON path did not surface OAuth2Error: err=%v", err)
	}
}

// And the JSON path still surfaces the Vextura envelope path (backward compat).
func TestIssueToken_JSONPath_VexturaEnvelope(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `{"code":"FORBIDDEN","message":"not allowed"}`)
	}))
	defer srv.Close()

	c := New(srv.URL, "")
	_, err := c.IssueToken(context.Background(), TokenRequest{GrantType: "refresh_token"})
	if err == nil {
		t.Fatal("want error")
	}
	if !errors.Is(err, ErrForbidden) {
		t.Errorf("errors.Is(err, ErrForbidden) false, err=%v", err)
	}
}

// Backward-compat sanity: IssueToken success path still sends JSON body.
func TestIssueToken_JSONPath_Success(t *testing.T) {
	t.Parallel()
	var gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(TokenResponse{AccessToken: "AT"})
	}))
	defer srv.Close()

	c := New(srv.URL, "")
	out, err := c.IssueToken(context.Background(), TokenRequest{GrantType: "refresh_token", RefreshToken: "rt"})
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if out.AccessToken != "AT" {
		t.Errorf("response not decoded: %+v", out)
	}
	if !strings.Contains(gotBody, `"grant_type":"refresh_token"`) {
		t.Errorf("JSON body malformed: %s", gotBody)
	}
}

// -------- RevokeTokenForm: encoding + no-info-leak semantics --------

// Happy path: server accepts a known token and returns 200 with an empty
// body. Method must return nil. Form body and headers must match RFC 7009.
func TestRevokeTokenForm_KnownToken200(t *testing.T) {
	t.Parallel()

	var gotForm url.Values
	var gotCT, gotAccept, gotAuth, gotPath, gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotMethod = r.Method
		gotCT = r.Header.Get("Content-Type")
		gotAccept = r.Header.Get("Accept")
		gotAuth = r.Header.Get("Authorization")
		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm: %v", err)
		}
		gotForm = r.PostForm
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := New(srv.URL, "adminBearer")
	err := c.RevokeTokenForm(context.Background(), RevokeRequest{
		Token:         "rt-xyz",
		TokenTypeHint: "refresh_token",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotPath != "/auth/revoke" {
		t.Errorf("path=%q, want /auth/revoke", gotPath)
	}
	if gotMethod != "POST" {
		t.Errorf("method=%q, want POST", gotMethod)
	}
	if gotCT != "application/x-www-form-urlencoded" {
		t.Errorf("Content-Type=%q, want application/x-www-form-urlencoded", gotCT)
	}
	if gotAccept != "application/json" {
		t.Errorf("Accept=%q, want application/json", gotAccept)
	}
	if gotAuth != "Bearer adminBearer" {
		t.Errorf("Authorization=%q, want Bearer adminBearer", gotAuth)
	}
	if gotForm.Get("token") != "rt-xyz" {
		t.Errorf("token=%q, want rt-xyz", gotForm.Get("token"))
	}
	if gotForm.Get("token_type_hint") != "refresh_token" {
		t.Errorf("token_type_hint=%q, want refresh_token", gotForm.Get("token_type_hint"))
	}
}

// RFC 7009 §2.2: server MUST return 200 for both known and unknown tokens.
// The SDK MUST NOT distinguish either — no error on unknown token. This is
// the load-bearing security property (no token-existence leak).
func TestRevokeTokenForm_UnknownToken200NoInfoLeak(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate vex-auth's "unknown token" branch: still 200, empty body.
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := New(srv.URL, "")
	err := c.RevokeTokenForm(context.Background(), RevokeRequest{
		Token: "garbage-never-issued",
	})
	if err != nil {
		t.Errorf("RFC 7009 §2.2 violation: unknown-token must return nil, got %v", err)
	}
}

// 204 No Content is also a legal success — some gate proxies rewrite 200
// with empty body to 204. Accept both, still nil.
func TestRevokeTokenForm_204Success(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c := New(srv.URL, "")
	if err := c.RevokeTokenForm(context.Background(), RevokeRequest{Token: "rt"}); err != nil {
		t.Errorf("204 should be treated as success, got %v", err)
	}
}

// Missing token → local invalid_request error BEFORE any HTTP call.
// Verifies we don't waste a round-trip and that the caller can pattern-match
// the OAuth2Error identically whether the check is client- or server-side.
func TestRevokeTokenForm_MissingTokenLocalError(t *testing.T) {
	t.Parallel()

	var called bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := New(srv.URL, "")
	err := c.RevokeTokenForm(context.Background(), RevokeRequest{})
	if err == nil {
		t.Fatal("want error, got nil")
	}
	oe, ok := IsOAuth2Error(err)
	if !ok {
		t.Fatalf("want *OAuth2Error, got %v (%T)", err, err)
	}
	if oe.Code != "invalid_request" {
		t.Errorf("Code=%q, want invalid_request", oe.Code)
	}
	if called {
		t.Errorf("local validation must short-circuit before HTTP call")
	}
}

// 401 invalid_client → decoded as *OAuth2Error with the RFC 6749 §5.2 code.
// Exercises the shared error decoder path for the revoke endpoint.
func TestRevokeTokenForm_InvalidClient(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"error":"invalid_client","error_description":"unknown client"}`)
	}))
	defer srv.Close()

	c := New(srv.URL, "")
	err := c.RevokeTokenForm(context.Background(), RevokeRequest{Token: "rt"})
	if err == nil {
		t.Fatal("want error")
	}
	oe, ok := IsOAuth2Error(err)
	if !ok {
		t.Fatalf("want *OAuth2Error, got %v (%T)", err, err)
	}
	if oe.Code != "invalid_client" {
		t.Errorf("Code=%q, want invalid_client", oe.Code)
	}
	if oe.HTTPStatus != http.StatusUnauthorized {
		t.Errorf("HTTPStatus=%d, want 401", oe.HTTPStatus)
	}
}

// 400 unsupported_token_type per RFC 7009 §2.2.1 — this is the one error
// code specific to /revoke (as opposed to /token). Confirms the decoder
// surfaces revocation-specific errors just like grant errors.
func TestRevokeTokenForm_UnsupportedTokenType(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"error":"unsupported_token_type","error_description":"server does not support this token type"}`)
	}))
	defer srv.Close()

	c := New(srv.URL, "")
	err := c.RevokeTokenForm(context.Background(), RevokeRequest{
		Token:         "rt",
		TokenTypeHint: "phantom_token",
	})
	oe, ok := IsOAuth2Error(err)
	if !ok {
		t.Fatalf("want *OAuth2Error, got %v (%T)", err, err)
	}
	if oe.Code != "unsupported_token_type" {
		t.Errorf("Code=%q, want unsupported_token_type", oe.Code)
	}
}

// ClientID + ClientSecret round-trip verifies public-client authentication
// flows: vex-mcp-server and vexctl talk to /auth/revoke without a Bearer,
// only a client_id (and optionally client_secret) in the form.
func TestRevokeTokenForm_ClientCredsPassthrough(t *testing.T) {
	t.Parallel()
	var gotForm url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotForm = r.PostForm
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := New(srv.URL, "") // no Bearer — public client
	err := c.RevokeTokenForm(context.Background(), RevokeRequest{
		Token:        "rt",
		ClientID:     "vexctl-cli",
		ClientSecret: "s3cret",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotForm.Get("client_id") != "vexctl-cli" {
		t.Errorf("client_id=%q, want vexctl-cli", gotForm.Get("client_id"))
	}
	if gotForm.Get("client_secret") != "s3cret" {
		t.Errorf("client_secret=%q, want s3cret", gotForm.Get("client_secret"))
	}
}

// Empty optional fields must be OMITTED, not sent blank. Same rationale as
// IssueTokenForm — a server-side validation that rejects blank client_id
// is more useful than one that silently accepts it as authentic-but-empty.
func TestRevokeTokenForm_OmitsEmptyFields(t *testing.T) {
	t.Parallel()
	var gotForm url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotForm = r.PostForm
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := New(srv.URL, "")
	err := c.RevokeTokenForm(context.Background(), RevokeRequest{Token: "rt-only"})
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if len(gotForm) != 1 {
		t.Errorf("want only 'token' field, got %d keys (%v)", len(gotForm), keys(gotForm))
	}
	if gotForm.Get("token") != "rt-only" {
		t.Errorf("token=%q, want rt-only", gotForm.Get("token"))
	}
	for _, absent := range []string{"token_type_hint", "client_id", "client_secret"} {
		if _, present := gotForm[absent]; present {
			t.Errorf("%s must be omitted when empty, got form=%v", absent, gotForm)
		}
	}
}

// Verify the raw form body wire shape (not just parsed values). RFC 7009
// §2.1 shows `token=45ghiukldjahdnhzdauz&token_type_hint=refresh_token`
// — confirm we emit percent-encoded pairs joined by '&'.
func TestRevokeTokenForm_RawWireFormat(t *testing.T) {
	t.Parallel()
	var rawBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		rawBody = string(b)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := New(srv.URL, "")
	err := c.RevokeTokenForm(context.Background(), RevokeRequest{
		Token:         "abc123",
		TokenTypeHint: "refresh_token",
	})
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	// Both key-value pairs must be present, joined by '&'.
	if !strings.Contains(rawBody, "token=abc123") {
		t.Errorf("body missing token pair: %q", rawBody)
	}
	if !strings.Contains(rawBody, "token_type_hint=refresh_token") {
		t.Errorf("body missing token_type_hint pair: %q", rawBody)
	}
	if !strings.Contains(rawBody, "&") {
		t.Errorf("body missing '&' separator: %q", rawBody)
	}
}

// Regression tripwire: the JSON RevokeToken path (from v0.2.0, generated
// in operations.go) MUST keep its current signature and JSON body shape.
// This test guards against an accidental codegen re-run that changes the
// RevokeToken wire format and silently breaks legacy callers who chose the
// JSON path deliberately (RevokeTokenForm is additive).
func TestRevokeToken_JSONPath_UnchangedWireShape(t *testing.T) {
	t.Parallel()
	var gotCT, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCT = r.Header.Get("Content-Type")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{}`)
	}))
	defer srv.Close()

	c := New(srv.URL, "")
	_, err := c.RevokeToken(context.Background(), RevokeTokenRequest{
		Token:         "rt",
		TokenTypeHint: "refresh_token",
	})
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if gotCT != "application/json" {
		t.Errorf("RevokeToken must remain JSON path, got Content-Type=%q", gotCT)
	}
	if !strings.Contains(gotBody, `"token":"rt"`) {
		t.Errorf("RevokeToken JSON body malformed: %s", gotBody)
	}
}

// -------- helpers --------

func keys(m url.Values) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
