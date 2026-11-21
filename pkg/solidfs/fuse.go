package solidfs

import (
	"context"
	"errors"
	"math"
	"sort"
	"strings"
	"sync"
	"syscall"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
)

// podFS serializes read-modify-write operations across all nodes of a mount.
type podFS struct {
	pod *Pod
	mu  sync.Mutex
}

type podNode struct {
	fs.Inode
	fsys *podFS
	path string
}

// NewFS returns the root node of a FUSE filesystem backed by p.
func NewFS(p *Pod) fs.InodeEmbedder {
	return &podNode{fsys: &podFS{pod: p}}
}

func podErr(err error) syscall.Errno {
	if err == nil {
		return 0
	}
	var errno syscall.Errno
	if errors.As(err, &errno) && errno != 0 {
		return errno
	}
	if errors.Is(err, context.Canceled) {
		return syscall.EINTR
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return syscall.ETIMEDOUT
	}
	return syscall.EIO
}

func childPath(parent, name string) (string, syscall.Errno) {
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\x00") {
		return "", syscall.EINVAL
	}
	if parent == "" {
		return name, 0
	}
	return parent + "/" + name, 0
}

func entryMode(e Entry) uint32 {
	if e.Dir {
		return syscall.S_IFDIR | 0755
	}
	return syscall.S_IFREG | 0644
}

func entryAttr(e Entry, out *fuse.Attr) {
	out.Mode = entryMode(e)
	out.Size = 0
	if e.Size > 0 {
		out.Size = uint64(e.Size)
	}
	out.SetTimes(nil, &e.ModTime, nil)
}

func (n *podNode) Getattr(ctx context.Context, _ fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	e, err := n.fsys.pod.Stat(ctx, n.path)
	if err != nil {
		return podErr(err)
	}
	entryAttr(e, &out.Attr)
	return 0
}

func (n *podNode) Lookup(ctx context.Context, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	p, errno := childPath(n.path, name)
	if errno != 0 {
		return nil, errno
	}
	e, err := n.fsys.pod.Stat(ctx, p)
	if err != nil {
		return nil, podErr(err)
	}
	entryAttr(e, &out.Attr)
	return n.NewInode(ctx, &podNode{fsys: n.fsys, path: p}, fs.StableAttr{Mode: entryMode(e)}), 0
}

func (n *podNode) Readdir(ctx context.Context) (fs.DirStream, syscall.Errno) {
	entries, err := n.fsys.pod.List(ctx, n.path)
	if err != nil {
		return nil, podErr(err)
	}
	dirs := make([]fuse.DirEntry, 0, len(entries))
	for _, e := range entries {
		dirs = append(dirs, fuse.DirEntry{Name: e.Name, Mode: entryMode(e)})
	}
	sort.Slice(dirs, func(i, j int) bool { return dirs[i].Name < dirs[j].Name })
	return fs.NewListDirStream(dirs), 0
}

func (n *podNode) Open(ctx context.Context, flags uint32) (fs.FileHandle, uint32, syscall.Errno) {
	if flags&syscall.O_TRUNC != 0 {
		n.fsys.mu.Lock()
		err := n.fsys.pod.Write(ctx, n.path, []byte{}, false)
		n.fsys.mu.Unlock()
		if err != nil {
			return nil, 0, podErr(err)
		}
	}
	return nil, fuse.FOPEN_DIRECT_IO, 0
}

func (n *podNode) Read(ctx context.Context, _ fs.FileHandle, dest []byte, off int64) (fuse.ReadResult, syscall.Errno) {
	if off < 0 {
		return nil, syscall.EINVAL
	}
	n.fsys.mu.Lock()
	data, err := n.fsys.pod.Read(ctx, n.path)
	if err == nil {
		data = append([]byte(nil), data...)
	}
	n.fsys.mu.Unlock()
	if err != nil {
		return nil, podErr(err)
	}
	if off >= int64(len(data)) {
		return fuse.ReadResultData(nil), 0
	}
	end := off + int64(len(dest))
	if end < off || end > int64(len(data)) {
		end = int64(len(data))
	}
	return fuse.ReadResultData(data[off:end]), 0
}

func (n *podNode) Write(ctx context.Context, _ fs.FileHandle, data []byte, off int64) (uint32, syscall.Errno) {
	if off < 0 {
		return 0, syscall.EINVAL
	}
	maxInt := uint64(int(^uint(0) >> 1))
	if uint64(len(data)) > math.MaxUint32 || uint64(len(data)) > maxInt || uint64(off) > maxInt-uint64(len(data)) {
		return 0, syscall.EFBIG
	}
	n.fsys.mu.Lock()
	defer n.fsys.mu.Unlock()
	old, err := n.fsys.pod.Read(ctx, n.path)
	if err != nil {
		return 0, podErr(err)
	}
	if len(data) == 0 {
		return 0, 0
	}
	end := int(off) + len(data)
	size := len(old)
	if end > size {
		size = end
	}
	updated := make([]byte, size)
	copy(updated, old)
	copy(updated[int(off):], data)
	if err := n.fsys.pod.Write(ctx, n.path, updated, false); err != nil {
		return 0, podErr(err)
	}
	return uint32(len(data)), 0
}

func (n *podNode) Setattr(ctx context.Context, _ fs.FileHandle, in *fuse.SetAttrIn, out *fuse.AttrOut) syscall.Errno {
	size, ok := in.GetSize()
	if !ok {
		return syscall.ENOTSUP
	}
	if size > uint64(int(^uint(0)>>1)) {
		return syscall.EFBIG
	}
	n.fsys.mu.Lock()
	defer n.fsys.mu.Unlock()
	data, err := n.fsys.pod.Read(ctx, n.path)
	if err != nil {
		return podErr(err)
	}
	updated := make([]byte, int(size))
	copy(updated, data)
	if err := n.fsys.pod.Write(ctx, n.path, updated, false); err != nil {
		return podErr(err)
	}
	e, err := n.fsys.pod.Stat(ctx, n.path)
	if err != nil {
		return podErr(err)
	}
	entryAttr(e, &out.Attr)
	return 0
}

// Writes are committed synchronously, so there is no buffered data to flush.
func (n *podNode) Flush(context.Context, fs.FileHandle) syscall.Errno { return 0 }

func (n *podNode) Create(ctx context.Context, name string, flags, mode uint32, out *fuse.EntryOut) (*fs.Inode, fs.FileHandle, uint32, syscall.Errno) {
	p, errno := childPath(n.path, name)
	if errno != 0 {
		return nil, nil, 0, errno
	}
	n.fsys.mu.Lock()
	err := n.fsys.pod.Write(ctx, p, []byte{}, true)
	n.fsys.mu.Unlock()
	if err != nil {
		return nil, nil, 0, podErr(err)
	}
	inode, errno := n.Lookup(ctx, name, out)
	return inode, nil, fuse.FOPEN_DIRECT_IO, errno
}

func (n *podNode) Mkdir(ctx context.Context, name string, mode uint32, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	p, errno := childPath(n.path, name)
	if errno != 0 {
		return nil, errno
	}
	if err := n.fsys.pod.Mkdir(ctx, p); err != nil {
		return nil, podErr(err)
	}
	return n.Lookup(ctx, name, out)
}

func (n *podNode) Unlink(ctx context.Context, name string) syscall.Errno {
	p, errno := childPath(n.path, name)
	if errno != 0 {
		return errno
	}
	n.fsys.mu.Lock()
	defer n.fsys.mu.Unlock()
	return podErr(n.fsys.pod.Remove(ctx, p, false))
}

func (n *podNode) Rmdir(ctx context.Context, name string) syscall.Errno {
	p, errno := childPath(n.path, name)
	if errno != 0 {
		return errno
	}
	n.fsys.mu.Lock()
	defer n.fsys.mu.Unlock()
	return podErr(n.fsys.pod.Remove(ctx, p, true))
}
