package solidfs

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"syscall"
	"testing"
)

func TestPodOperations(t *testing.T) {
	var data string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer secret" {
			t.Error("missing authorization")
		}
		switch {
		case r.URL.Path == "/pod/" && r.Method == "GET":
			w.Header().Set("Content-Type", "text/turtle; charset=utf-8")
			fmt.Fprint(w, `@prefix ldp: <http://www.w3.org/ns/ldp#>. <> ldp:contains <a%20b.txt>, <dir/>, <nested/file>, <https://evil.example/x>.`)
		case r.URL.Path == "/pod/a b.txt" && r.Method == "PUT":
			if r.Header.Get("If-None-Match") != "*" {
				t.Error("missing creation precondition")
			}
			b, _ := io.ReadAll(r.Body)
			data = string(b)
			w.WriteHeader(201)
		case r.URL.Path == "/pod/a b.txt" && r.Method == "GET":
			fmt.Fprint(w, data)
		case r.URL.Path == "/pod/dir" && r.Method == "HEAD":
			http.Redirect(w, r, "/pod/dir/", 301)
		case r.URL.Path == "/pod/dir/" && r.Method == "HEAD":
			w.WriteHeader(200)
		case r.URL.Path == "/pod/new/" && r.Method == "PUT":
			if !strings.Contains(r.Header.Get("Link"), "BasicContainer") || r.Header.Get("If-None-Match") != "*" {
				t.Error("bad container headers")
			}
			w.WriteHeader(201)
		case r.URL.Path == "/pod/dir/" && r.Method == "DELETE":
			w.WriteHeader(409)
		default:
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	p, err := NewPod(server.URL+"/pod/", "secret")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	entries, err := p.List(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries[0].Name != "a b.txt" || entries[1].Name != "dir" || !entries[1].Dir {
		t.Fatalf("entries: %+v", entries)
	}
	if err := p.Write(ctx, "a b.txt", []byte("hello"), true); err != nil {
		t.Fatal(err)
	}
	b, err := p.Read(ctx, "a b.txt")
	if err != nil || string(b) != "hello" {
		t.Fatalf("read %q: %v", b, err)
	}
	e, err := p.Stat(ctx, "dir")
	if err != nil || !e.Dir {
		t.Fatalf("stat %+v: %v", e, err)
	}
	if err := p.Mkdir(ctx, "new"); err != nil {
		t.Fatal(err)
	}
	if err := p.Remove(ctx, "dir", true); !errors.Is(err, syscall.ENOTEMPTY) {
		t.Fatalf("remove: %v", err)
	}
	if _, err := p.Read(ctx, "../escape"); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("escape: %v", err)
	}
}

func TestPodRejectsInvalidURLs(t *testing.T) {
	for _, u := range []string{"file:///tmp", "https://user:pass@example.com/", "https://example.com/?x=1"} {
		if _, err := NewPod(u, ""); err == nil {
			t.Errorf("accepted %q", u)
		}
	}
}

type testAuthenticatedClient struct {
	called bool
}

func (c *testAuthenticatedClient) Do(req *http.Request) (*http.Response, error) {
	c.called = true
	return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("authenticated"))}, nil
}

func TestPodUsesAuthenticatedClient(t *testing.T) {
	p, err := NewPod("https://example.org/pod/", "")
	if err != nil {
		t.Fatal(err)
	}
	c := &testAuthenticatedClient{}
	p.auth = c
	data, err := p.Read(context.Background(), "file")
	if err != nil || !c.called || string(data) != "authenticated" {
		t.Fatalf("read = %q, called = %v, error = %v", data, c.called, err)
	}
}

func TestAuthenticateRejectsHTTPPod(t *testing.T) {
	p, err := NewPod("http://example.org/pod/", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Authenticate(context.Background(), "http://127.0.0.1:1", ""); err == nil || !strings.Contains(err.Error(), "HTTPS Pod URL") {
		t.Fatalf("Authenticate error = %v; want HTTPS requirement", err)
	}
}
