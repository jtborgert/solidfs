package solidfs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"path"
	"strings"
	"syscall"
	"time"

	"github.com/knakk/rdf"
)

const contains = "http://www.w3.org/ns/ldp#contains"

type Entry struct {
	Name    string
	Dir     bool
	Size    int64
	ModTime time.Time
}

type Pod struct {
	root   *url.URL
	client *http.Client
	token  string
	auth   interface {
		Do(*http.Request) (*http.Response, error)
	}
}

func NewPod(rawURL, token string) (*Pod, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u == nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("pod URL must be an HTTP(S) container URL without credentials, query, or fragment")
	}
	if !strings.HasSuffix(u.Path, "/") {
		u.Path += "/"
		u.RawPath = ""
	}
	return &Pod{root: u, token: token, client: &http.Client{Timeout: 60 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

// Authenticate performs interactive Solid-OIDC login for an HTTPS Pod.
// It must be called before the Pod is used concurrently.
func (p *Pod) Authenticate(ctx context.Context, issuer, clientID string) error {
	if p.root.Scheme != "https" {
		return errors.New("interactive authentication requires an HTTPS Pod URL")
	}
	auth, err := Login(ctx, issuer, clientID)
	if err != nil {
		return fmt.Errorf("login: %w", err)
	}
	p.auth = auth
	return nil
}

func (p *Pod) resource(name string, dir bool) (*url.URL, error) {
	if name != "" {
		for _, part := range strings.Split(name, "/") {
			if part == "" || part == "." || part == ".." {
				return nil, syscall.EINVAL
			}
		}
	}
	u := *p.root
	u.Path += name
	if dir && !strings.HasSuffix(u.Path, "/") {
		u.Path += "/"
	}
	u.RawPath = ""
	return &u, nil
}

func (p *Pod) request(ctx context.Context, method string, u *url.URL, body []byte, headers map[string]string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if p.token != "" {
		req.Header.Set("Authorization", "Bearer "+p.token)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	var resp *http.Response
	if p.auth != nil {
		resp, err = p.auth.Do(req)
	} else {
		resp, err = p.client.Do(req)
	}
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", method, u, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		resp.Body.Close()
		var e error
		switch resp.StatusCode {
		case 401, 403:
			e = syscall.EACCES
		case 301, 302, 307, 308, 404, 410:
			e = syscall.ENOENT
		case 405, 501:
			e = syscall.ENOTSUP
		case 409:
			e = syscall.ENOTEMPTY
		case 412:
			e = syscall.EEXIST
		case 413:
			e = syscall.EFBIG
		default:
			e = syscall.EIO
		}
		return nil, fmt.Errorf("%s %s: HTTP %d: %w", method, u, resp.StatusCode, e)
	}
	return resp, nil
}

func (p *Pod) Stat(ctx context.Context, name string) (Entry, error) {
	for _, dir := range []bool{false, true} {
		if name == "" && !dir {
			continue
		}
		u, err := p.resource(name, dir)
		if err != nil {
			return Entry{}, err
		}
		resp, err := p.request(ctx, http.MethodHead, u, nil, nil)
		if err != nil {
			if !dir && errors.Is(err, syscall.ENOENT) {
				continue
			}
			return Entry{}, err
		}
		resp.Body.Close()
		mod, _ := http.ParseTime(resp.Header.Get("Last-Modified"))
		size := resp.ContentLength
		if size < 0 || dir {
			size = 0
		}
		return Entry{Name: path.Base(name), Dir: dir, Size: size, ModTime: mod}, nil
	}
	return Entry{}, syscall.ENOENT
}

func (p *Pod) List(ctx context.Context, name string) ([]Entry, error) {
	u, err := p.resource(name, true)
	if err != nil {
		return nil, err
	}
	resp, err := p.request(ctx, http.MethodGet, u, nil, map[string]string{"Accept": "text/turtle"})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	typ, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if typ != "text/turtle" {
		return nil, fmt.Errorf("unsupported container content type %q: %w", typ, syscall.EIO)
	}
	dec := rdf.NewTripleDecoder(resp.Body, rdf.Turtle)
	base, err := rdf.NewIRI(u.String())
	if err != nil {
		return nil, err
	}
	if err := dec.SetOption(rdf.Base, base); err != nil {
		return nil, err
	}
	entries := []Entry{}
	seen := map[string]bool{}
	for {
		t, err := dec.Decode()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("parse container %s: %w", u, err)
		}
		if t.Pred.String() != contains || t.Subj.String() != u.String() {
			continue
		}
		child, err := url.Parse(t.Obj.String())
		if err != nil || child.Scheme != u.Scheme || child.Host != u.Host || child.RawQuery != "" || child.Fragment != "" || !strings.HasPrefix(child.Path, u.Path) {
			continue
		}
		rel := strings.TrimPrefix(child.Path, u.Path)
		dir := strings.HasSuffix(rel, "/")
		rel = strings.TrimSuffix(rel, "/")
		if rel == "" || rel == "." || rel == ".." || strings.Contains(rel, "/") || seen[rel] {
			continue
		}
		seen[rel] = true
		entries = append(entries, Entry{Name: rel, Dir: dir})
	}
	return entries, nil
}

func (p *Pod) Read(ctx context.Context, name string) ([]byte, error) {
	u, err := p.resource(name, false)
	if err != nil {
		return nil, err
	}
	resp, err := p.request(ctx, http.MethodGet, u, nil, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

func (p *Pod) Write(ctx context.Context, name string, data []byte, create bool) error {
	if name == "" {
		return syscall.EISDIR
	}
	u, err := p.resource(name, false)
	if err != nil {
		return err
	}
	typ := mime.TypeByExtension(path.Ext(name))
	if typ == "" {
		typ = "application/octet-stream"
	}
	headers := map[string]string{"Content-Type": typ}
	if create {
		headers["If-None-Match"] = "*"
	}
	resp, err := p.request(ctx, http.MethodPut, u, data, headers)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

func (p *Pod) Mkdir(ctx context.Context, name string) error {
	if name == "" {
		return syscall.EEXIST
	}
	u, err := p.resource(name, true)
	if err != nil {
		return err
	}
	resp, err := p.request(ctx, http.MethodPut, u, nil, map[string]string{"Content-Type": "text/turtle", "Link": "<http://www.w3.org/ns/ldp#BasicContainer>; rel=\"type\"", "If-None-Match": "*"})
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

func (p *Pod) Remove(ctx context.Context, name string, dir bool) error {
	if name == "" {
		return syscall.EPERM
	}
	u, err := p.resource(name, dir)
	if err != nil {
		return err
	}
	resp, err := p.request(ctx, http.MethodDelete, u, nil, nil)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}
