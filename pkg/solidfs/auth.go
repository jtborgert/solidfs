package solidfs

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

var authEncoding = base64.RawURLEncoding

type oidcMetadata struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	RegistrationEndpoint  string `json:"registration_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

// SolidAuth holds an in-memory DPoP key and tokens. It is safe for concurrent use.
type SolidAuth struct {
	mu                        sync.Mutex
	key                       *ecdsa.PrivateKey
	client                    *http.Client
	metadata                  oidcMetadata
	clientID                  string
	accessToken, refreshToken string
	expiry                    time.Time
	nonces                    map[string]string
}

func secureURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" || (u.Scheme != "https" && !(u.Scheme == "http" && (u.Hostname() == "localhost" || net.ParseIP(u.Hostname()) != nil && net.ParseIP(u.Hostname()).IsLoopback()))) {
		return nil, fmt.Errorf("invalid or insecure URL: %q", raw)
	}
	return u, nil
}

func randomString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return authEncoding.EncodeToString(b), nil
}

func jsonResponse(resp *http.Response, dst any) error {
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("server returned HTTP %d", resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(dst)
}

// Login performs interactive authorization. It prints a URL to stderr and waits
// for a loopback callback until ctx is canceled. Tokens are kept only in memory.
func Login(ctx context.Context, issuer, clientID string) (*SolidAuth, error) {
	u, err := secureURL(issuer)
	if err != nil || u.RawQuery != "" {
		return nil, errors.New("invalid issuer URL")
	}
	client := &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(issuer, "/")+"/.well-known/openid-configuration", nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	var m oidcMetadata
	if err = jsonResponse(resp, &m); err != nil {
		return nil, err
	}
	if m.Issuer != issuer {
		return nil, errors.New("discovery issuer mismatch")
	}
	for _, endpoint := range []string{m.AuthorizationEndpoint, m.TokenEndpoint, m.JWKSURI} {
		if _, err = secureURL(endpoint); err != nil {
			return nil, err
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	a := &SolidAuth{key: key, client: client, metadata: m, nonces: make(map[string]string)}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	defer listener.Close()
	redirect := "http://" + listener.Addr().String() + "/callback"
	if clientID == "" {
		if _, err = secureURL(m.RegistrationEndpoint); err != nil {
			return nil, errors.New("dynamic registration unavailable")
		}
		body, _ := json.Marshal(map[string]any{"client_name": "solidfs", "redirect_uris": []string{redirect}, "grant_types": []string{"authorization_code", "refresh_token"}, "response_types": []string{"code"}, "token_endpoint_auth_method": "none"})
		req, err = http.NewRequestWithContext(ctx, http.MethodPost, m.RegistrationEndpoint, strings.NewReader(string(body)))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err = client.Do(req)
		if err != nil {
			return nil, err
		}
		var registration struct {
			ClientID string `json:"client_id"`
		}
		if err = jsonResponse(resp, &registration); err != nil {
			return nil, err
		}
		clientID = registration.ClientID
		if clientID == "" {
			return nil, errors.New("registration returned no client ID")
		}
	}
	a.clientID = clientID
	state, err := randomString(32)
	if err != nil {
		return nil, err
	}
	nonce, err := randomString(32)
	if err != nil {
		return nil, err
	}
	verifier, err := randomString(32)
	if err != nil {
		return nil, err
	}
	challenge := sha256.Sum256([]byte(verifier))
	authURL, _ := url.Parse(m.AuthorizationEndpoint)
	q := authURL.Query()
	q.Set("response_type", "code")
	q.Set("client_id", clientID)
	q.Set("redirect_uri", redirect)
	q.Set("scope", "openid webid offline_access")
	q.Set("state", state)
	q.Set("nonce", nonce)
	q.Set("code_challenge", authEncoding.EncodeToString(challenge[:]))
	q.Set("code_challenge_method", "S256")
	authURL.RawQuery = q.Encode()
	type callback struct {
		code string
		err  error
	}
	callbacks := make(chan callback, 1)
	server := &http.Server{ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/callback" {
			http.NotFound(w, r)
			return
		}
		q := r.URL.Query()
		if len(q["state"]) != 1 || q.Get("state") != state {
			http.Error(w, "Invalid state", http.StatusBadRequest)
			return
		}
		result := callback{}
		if len(q["iss"]) > 1 || (q.Get("iss") != "" && q.Get("iss") != issuer) {
			result.err = errors.New("callback issuer mismatch")
		} else if q.Get("error") != "" {
			result.err = fmt.Errorf("authorization failed: %s", q.Get("error"))
		} else if len(q["code"]) != 1 || q.Get("code") == "" {
			result.err = errors.New("missing authorization code")
		} else {
			result.code = q.Get("code")
		}
		select {
		case callbacks <- result:
			fmt.Fprint(w, "Authorization received. You may close this window.")
		default:
			http.Error(w, "Already received", http.StatusBadRequest)
		}
	})}
	defer server.Close()
	serverErrors := make(chan error, 1)
	go func() { serverErrors <- server.Serve(listener) }()
	fmt.Fprintf(os.Stderr, "Open this URL to authorize solidfs:\n%s\n", authURL.String())
	var result callback
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case err := <-serverErrors:
		return nil, err
	case result = <-callbacks:
	}
	if result.err != nil {
		return nil, result.err
	}
	values := url.Values{"grant_type": {"authorization_code"}, "code": {result.code}, "redirect_uri": {redirect}, "client_id": {clientID}, "code_verifier": {verifier}}
	token, err := a.tokenRequest(ctx, values)
	if err != nil {
		return nil, err
	}
	if err = a.validateIDToken(ctx, token.IDToken, nonce); err != nil {
		return nil, err
	}
	if err = a.storeToken(token, false); err != nil {
		return nil, err
	}
	return a, nil
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
	IDToken      string `json:"id_token"`
	Error        string `json:"error"`
}

func (a *SolidAuth) storeToken(t tokenResponse, refresh bool) error {
	if t.AccessToken == "" || !strings.EqualFold(t.TokenType, "DPoP") || t.ExpiresIn <= 0 || t.ExpiresIn > int64((365*24*time.Hour)/time.Second) {
		return errors.New("invalid DPoP token response")
	}
	a.accessToken = t.AccessToken
	if t.RefreshToken != "" || !refresh {
		a.refreshToken = t.RefreshToken
	}
	a.expiry = time.Now().Add(time.Duration(t.ExpiresIn) * time.Second)
	return nil
}

func origin(u *url.URL) string { return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host) }

func (a *SolidAuth) proof(method string, u *url.URL, token, nonce string) (string, error) {
	x := a.key.PublicKey.X.FillBytes(make([]byte, 32))
	y := a.key.PublicKey.Y.FillBytes(make([]byte, 32))
	header := map[string]any{"typ": "dpop+jwt", "alg": "ES256", "jwk": map[string]string{"kty": "EC", "crv": "P-256", "x": authEncoding.EncodeToString(x), "y": authEncoding.EncodeToString(y)}}
	id, err := randomString(32)
	if err != nil {
		return "", err
	}
	uri := *u
	uri.RawQuery = ""
	uri.ForceQuery = false
	uri.Fragment = ""
	if uri.Path == "" {
		uri.Path = "/"
	}
	claims := map[string]any{"jti": id, "htm": method, "htu": uri.String(), "iat": time.Now().Unix()}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	if token != "" {
		h := sha256.Sum256([]byte(token))
		claims["ath"] = authEncoding.EncodeToString(h[:])
	}
	h, _ := json.Marshal(header)
	c, _ := json.Marshal(claims)
	input := authEncoding.EncodeToString(h) + "." + authEncoding.EncodeToString(c)
	digest := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, a.key, digest[:])
	if err != nil {
		return "", err
	}
	sig := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	return input + "." + authEncoding.EncodeToString(sig), nil
}

func (a *SolidAuth) tokenRequest(ctx context.Context, values url.Values) (tokenResponse, error) {
	var t tokenResponse
	u, _ := url.Parse(a.metadata.TokenEndpoint)
	for attempt := 0; attempt < 2; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), strings.NewReader(values.Encode()))
		if err != nil {
			return t, err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		proof, err := a.proof(req.Method, u, "", a.nonces[origin(u)])
		if err != nil {
			return t, err
		}
		req.Header.Set("DPoP", proof)
		resp, err := a.client.Do(req)
		if err != nil {
			return t, err
		}
		nonce := resp.Header.Get("DPoP-Nonce")
		if nonce != "" {
			a.nonces[origin(u)] = nonce
		}
		var current tokenResponse
		err = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&current)
		resp.Body.Close()
		if attempt == 0 && (resp.StatusCode == 400 || resp.StatusCode == 401) && current.Error == "use_dpop_nonce" && nonce != "" {
			continue
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return t, fmt.Errorf("token endpoint returned HTTP %d (%s)", resp.StatusCode, current.Error)
		}
		if err != nil {
			return t, err
		}
		return current, nil
	}
	return t, errors.New("token nonce retry failed")
}

// Do signs a request with DPoP. Redirects are returned to the caller, never followed.
// A nonce challenge is retried once only when the request body can be replayed.
func (a *SolidAuth) Do(req *http.Request) (*http.Response, error) {
	if req == nil || req.URL == nil {
		return nil, errors.New("nil request")
	}
	if _, err := secureURL(req.URL.String()); err != nil {
		return nil, err
	}
	if req.Host != "" && !strings.EqualFold(req.Host, req.URL.Host) {
		return nil, errors.New("request Host must match URL host")
	}
	a.mu.Lock()
	if time.Now().After(a.expiry) || (a.refreshToken != "" && time.Until(a.expiry) <= 30*time.Second) {
		if a.refreshToken == "" {
			a.mu.Unlock()
			return nil, errors.New("access token expired or expiring and no refresh token available")
		}
		t, err := a.tokenRequest(req.Context(), url.Values{"grant_type": {"refresh_token"}, "refresh_token": {a.refreshToken}, "client_id": {a.clientID}})
		if err == nil {
			err = a.storeToken(t, true)
		}
		if err != nil {
			a.mu.Unlock()
			return nil, err
		}
	}
	token := a.accessToken
	a.mu.Unlock()
	for attempt := 0; attempt < 2; attempt++ {
		r := req.Clone(req.Context())
		if r.Method == "" {
			r.Method = http.MethodGet
		}
		if r.Header == nil {
			r.Header = make(http.Header)
		}
		if attempt > 0 && req.Body != nil && req.Body != http.NoBody {
			var err error
			r.Body, err = req.GetBody()
			if err != nil {
				return nil, err
			}
		}
		a.mu.Lock()
		proof, err := a.proof(r.Method, r.URL, token, a.nonces[origin(r.URL)])
		a.mu.Unlock()
		if err != nil {
			return nil, err
		}
		r.Header.Set("Authorization", "DPoP "+token)
		r.Header.Set("DPoP", proof)
		resp, err := a.client.Do(r)
		if err != nil {
			return nil, err
		}
		nonce := resp.Header.Get("DPoP-Nonce")
		if nonce != "" {
			a.mu.Lock()
			a.nonces[origin(r.URL)] = nonce
			a.mu.Unlock()
		}
		if attempt == 0 && resp.StatusCode == http.StatusUnauthorized && nonce != "" && strings.Contains(strings.ToLower(resp.Header.Get("WWW-Authenticate")), "use_dpop_nonce") && (req.Body == nil || req.Body == http.NoBody || req.GetBody != nil) {
			resp.Body.Close()
			continue
		}
		return resp, nil
	}
	return nil, errors.New("nonce retry failed")
}

func (a *SolidAuth) validateIDToken(ctx context.Context, raw, nonce string) error {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return errors.New("invalid ID token")
	}
	headerBytes, err := authEncoding.DecodeString(parts[0])
	if err != nil {
		return err
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if json.Unmarshal(headerBytes, &header) != nil || (header.Alg != "RS256" && header.Alg != "ES256") {
		return errors.New("unsupported ID token algorithm")
	}
	claimsBytes, err := authEncoding.DecodeString(parts[1])
	if err != nil {
		return err
	}
	var claims struct {
		Iss   string          `json:"iss"`
		Sub   string          `json:"sub"`
		Aud   json.RawMessage `json:"aud"`
		Azp   string          `json:"azp"`
		Exp   int64           `json:"exp"`
		Iat   int64           `json:"iat"`
		Nonce string          `json:"nonce"`
	}
	if json.Unmarshal(claimsBytes, &claims) != nil || claims.Iss != a.metadata.Issuer || claims.Sub == "" || claims.Nonce != nonce || claims.Exp <= time.Now().Unix() || claims.Iat <= 0 || claims.Iat > time.Now().Add(time.Minute).Unix() {
		return errors.New("invalid ID token claims")
	}
	var aud []string
	var single string
	if json.Unmarshal(claims.Aud, &single) == nil {
		aud = []string{single}
	} else if json.Unmarshal(claims.Aud, &aud) != nil {
		return errors.New("invalid ID token audience")
	}
	found := false
	for _, v := range aud {
		if v == a.clientID {
			found = true
		}
	}
	if !found || (len(aud) > 1 && claims.Azp != a.clientID) || (claims.Azp != "" && claims.Azp != a.clientID) {
		return errors.New("invalid ID token audience")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.metadata.JWKSURI, nil)
	if err != nil {
		return err
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return err
	}
	var jwks struct {
		Keys []struct{ Kty, Kid, Use, Alg, Crv, X, Y, N, E string } `json:"keys"`
	}
	if err = jsonResponse(resp, &jwks); err != nil {
		return err
	}
	sig, err := authEncoding.DecodeString(parts[2])
	if err != nil {
		return err
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	for _, k := range jwks.Keys {
		if (header.Kid != "" && k.Kid != header.Kid) || (k.Use != "" && k.Use != "sig") || (k.Alg != "" && k.Alg != header.Alg) {
			continue
		}
		if header.Alg == "ES256" && k.Kty == "EC" && k.Crv == "P-256" && len(sig) == 64 {
			x, ex := authEncoding.DecodeString(k.X)
			y, ey := authEncoding.DecodeString(k.Y)
			if ex == nil && ey == nil && len(x) == 32 && len(y) == 32 {
				pub := ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
				if pub.Curve.IsOnCurve(pub.X, pub.Y) && ecdsa.Verify(&pub, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
					return nil
				}
			}
		}
		if header.Alg == "RS256" && k.Kty == "RSA" {
			n, en := authEncoding.DecodeString(k.N)
			e, ee := authEncoding.DecodeString(k.E)
			if en == nil && ee == nil && len(n) >= 256 && len(e) > 0 && len(e) <= 4 {
				exponent := new(big.Int).SetBytes(e)
				if exponent.IsInt64() && exponent.Int64() >= 3 && exponent.Int64() <= int64(^uint32(0)) {
					pub := rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(exponent.Int64())}
					if rsa.VerifyPKCS1v15(&pub, crypto.SHA256, digest[:], sig) == nil {
						return nil
					}
				}
			}
		}
	}
	return errors.New("ID token signature verification failed")
}
