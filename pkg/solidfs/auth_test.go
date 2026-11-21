package solidfs

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

func proofClaims(t *testing.T, raw string) map[string]any {
	t.Helper()
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		t.Fatal("invalid proof")
	}
	b, err := authEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err = json.Unmarshal(b, &claims); err != nil {
		t.Fatal(err)
	}
	return claims
}

func TestInteractiveLoginRefreshAndNonce(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var server *httptest.Server
	var authQuery url.Values
	tokenCalls, resourceCalls := 0, 0
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			json.NewEncoder(w).Encode(oidcMetadata{Issuer: server.URL, AuthorizationEndpoint: server.URL + "/authorize", TokenEndpoint: server.URL + "/token", JWKSURI: server.URL + "/keys", RegistrationEndpoint: server.URL + "/register"})
		case "/register":
			json.NewEncoder(w).Encode(map[string]string{"client_id": "client"})
		case "/keys":
			json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]string{"kty": "EC", "crv": "P-256", "kid": "key", "x": authEncoding.EncodeToString(key.X.FillBytes(make([]byte, 32))), "y": authEncoding.EncodeToString(key.Y.FillBytes(make([]byte, 32)))}}})
		case "/token":
			tokenCalls++
			claims := proofClaims(t, r.Header.Get("DPoP"))
			if claims["htm"] != "POST" || claims["htu"] != server.URL+"/token" || claims["ath"] != nil {
				t.Error("incorrect token proof", claims)
			}
			if tokenCalls == 1 {
				w.Header().Set("DPoP-Nonce", "token-nonce")
				w.WriteHeader(400)
				fmt.Fprint(w, `{"error":"use_dpop_nonce"}`)
				return
			}
			if claims["nonce"] != "token-nonce" {
				t.Error("missing token nonce", claims)
			}
			r.ParseForm()
			if r.Form.Get("grant_type") == "refresh_token" {
				if r.Form.Get("refresh_token") != "refresh" {
					t.Error("wrong refresh token")
				}
				json.NewEncoder(w).Encode(map[string]any{"access_token": "new", "token_type": "DPoP", "expires_in": 3600})
				return
			}
			h := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
			if authEncoding.EncodeToString(h[:]) != authQuery.Get("code_challenge") || r.Form.Get("code") != "code" {
				t.Error("bad PKCE or code")
			}
			header, _ := json.Marshal(map[string]string{"alg": "ES256", "kid": "key"})
			body, _ := json.Marshal(map[string]any{"iss": server.URL, "sub": "user", "aud": "client", "nonce": authQuery.Get("nonce"), "iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix()})
			input := authEncoding.EncodeToString(header) + "." + authEncoding.EncodeToString(body)
			digest := sha256.Sum256([]byte(input))
			x, y, _ := ecdsa.Sign(rand.Reader, key, digest[:])
			sig := append(x.FillBytes(make([]byte, 32)), y.FillBytes(make([]byte, 32))...)
			json.NewEncoder(w).Encode(map[string]any{"access_token": "old", "refresh_token": "refresh", "token_type": "DPoP", "expires_in": 3600, "id_token": input + "." + authEncoding.EncodeToString(sig)})
		case "/resource":
			resourceCalls++
			claims := proofClaims(t, r.Header.Get("DPoP"))
			hash := sha256.Sum256([]byte("new"))
			if r.Header.Get("Authorization") != "DPoP new" || claims["ath"] != authEncoding.EncodeToString(hash[:]) || claims["htu"] != server.URL+"/resource" {
				t.Error("bad resource proof", claims)
			}
			if resourceCalls == 1 {
				w.Header().Set("DPoP-Nonce", "resource-nonce")
				w.Header().Set("WWW-Authenticate", `DPoP error="use_dpop_nonce"`)
				w.WriteHeader(401)
				return
			}
			if claims["nonce"] != "resource-nonce" {
				t.Error("missing resource nonce")
			}
			b, _ := io.ReadAll(r.Body)
			if string(b) != "payload" {
				t.Error("body not replayed")
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	oldStderr := os.Stderr
	os.Stderr = writer
	defer func() { os.Stderr = oldStderr; reader.Close(); writer.Close() }()
	type result struct {
		auth *SolidAuth
		err  error
	}
	done := make(chan result, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go func() { a, e := Login(ctx, server.URL, ""); done <- result{a, e} }()
	scanner := bufio.NewScanner(reader)
	if !scanner.Scan() || !scanner.Scan() {
		t.Fatal("missing login URL")
	}
	u, err := url.Parse(scanner.Text())
	if err != nil {
		t.Fatal(err)
	}
	authQuery = u.Query()
	callback, _ := url.Parse(authQuery.Get("redirect_uri"))
	q := callback.Query()
	q.Set("state", "wrong")
	q.Set("code", "code")
	callback.RawQuery = q.Encode()
	resp, err := http.Get(callback.String())
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatal("accepted incorrect state")
	}
	q.Set("state", authQuery.Get("state"))
	q.Set("code", "code")
	callback.RawQuery = q.Encode()
	resp, err = http.Get(callback.String())
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	r := <-done
	if r.err != nil {
		t.Fatal(r.err)
	}
	r.auth.expiry = time.Now().Add(-time.Second)
	req, _ := http.NewRequest("POST", server.URL+"/resource?query=ignored", strings.NewReader("payload"))
	resp, err = r.auth.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 || tokenCalls != 3 || resourceCalls != 2 {
		t.Fatalf("status %d token calls %d resource calls %d", resp.StatusCode, tokenCalls, resourceCalls)
	}
}

func TestAuthRejectsInsecureAndInvalidTokens(t *testing.T) {
	for _, u := range []string{"http://example.com", "https://user@example.com", "https://example.com/#fragment"} {
		if _, err := secureURL(u); err == nil {
			t.Errorf("accepted %s", u)
		}
	}
	a := &SolidAuth{}
	for _, token := range []tokenResponse{{AccessToken: "x", TokenType: "Bearer", ExpiresIn: 3600}, {AccessToken: "x", TokenType: "DPoP"}} {
		if a.storeToken(token, false) == nil {
			t.Error("accepted invalid token")
		}
	}
	if err := a.validateIDToken(context.Background(), "invalid", "nonce"); err == nil {
		t.Error("accepted invalid ID token")
	}
}

func TestDoDoesNotReplayUnrewindableBodyOrFollowRedirect(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/target", http.StatusFound)
			return
		}
		w.Header().Set("DPoP-Nonce", "nonce")
		w.Header().Set("WWW-Authenticate", `DPoP error="use_dpop_nonce"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()
	a := &SolidAuth{key: key, client: &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, accessToken: "token", expiry: time.Now().Add(time.Hour), nonces: make(map[string]string)}
	req, _ := http.NewRequest("POST", server.URL, io.NopCloser(strings.NewReader("body")))
	resp, err := a.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 401 || calls != 1 {
		t.Fatal("unrewindable request was retried")
	}
	req, _ = http.NewRequest("GET", server.URL+"/redirect", nil)
	resp, err = a.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 302 || calls != 2 {
		t.Fatal("redirect was followed")
	}
}
