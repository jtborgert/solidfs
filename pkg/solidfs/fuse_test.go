package solidfs

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"syscall"
	"testing"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"
)

func TestChildPath(t *testing.T) {
	for _, tc := range []struct {
		parent, name, want string
		errno              syscall.Errno
	}{
		{"", "file", "file", 0},
		{"dir/sub", "file", "dir/sub/file", 0},
		{"", "..", "", syscall.EINVAL},
		{"", "a/b", "", syscall.EINVAL},
		{"", "", "", syscall.EINVAL},
	} {
		got, errno := childPath(tc.parent, tc.name)
		if got != tc.want || errno != tc.errno {
			t.Errorf("childPath(%q, %q) = %q, %v; want %q, %v", tc.parent, tc.name, got, errno, tc.want, tc.errno)
		}
	}
}

func TestPodErr(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want syscall.Errno
	}{
		{nil, 0},
		{fmt.Errorf("wrapped: %w", syscall.ENOENT), syscall.ENOENT},
		{context.Canceled, syscall.EINTR},
		{context.DeadlineExceeded, syscall.ETIMEDOUT},
		{fmt.Errorf("unknown"), syscall.EIO},
	} {
		if got := podErr(tc.err); got != tc.want {
			t.Errorf("podErr(%v) = %v; want %v", tc.err, got, tc.want)
		}
	}
}

func TestEntryAttr(t *testing.T) {
	modified := time.Unix(123, 456)
	out := fuse.Attr{Size: 99}
	entryAttr(Entry{Dir: true, ModTime: modified}, &out)
	if out.Mode != syscall.S_IFDIR|0755 || out.Size != 0 || out.Mtime != 123 || out.Mtimensec != 456 {
		t.Fatalf("directory attributes: %+v", out)
	}
	entryAttr(Entry{Size: 42, ModTime: modified}, &out)
	if out.Mode != syscall.S_IFREG|0644 || out.Size != 42 {
		t.Fatalf("file attributes: %+v", out)
	}
}

func TestFileWrites(t *testing.T) {
	data := []byte("hello")
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			_, _ = w.Write(data)
		case http.MethodPut:
			data, _ = io.ReadAll(r.Body)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer s.Close()
	p, err := NewPod(s.URL+"/", "")
	if err != nil {
		t.Fatal(err)
	}
	n := &podNode{fsys: &podFS{pod: p}, path: "file"}
	if count, errno := n.Write(context.Background(), nil, []byte("!"), 7); errno != 0 || count != 1 {
		t.Fatalf("write = %d, %v", count, errno)
	}
	if string(data) != "hello\x00\x00!" {
		t.Fatalf("unexpected data %q", data)
	}
	if _, _, errno := n.Open(context.Background(), syscall.O_TRUNC); errno != 0 || len(data) != 0 {
		t.Fatalf("truncate: %v, data %q", errno, data)
	}
}
