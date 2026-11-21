package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
	"solidfs/pkg/solidfs"
)

func main() {
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: solidfs [options] POD_URL MOUNTPOINT\n")
		flag.PrintDefaults()
	}
	debug := flag.Bool("debug", false, "enable FUSE debug logging")
	issuer := flag.String("issuer", "", "Solid OIDC issuer URL (enables interactive login)")
	clientID := flag.String("client-id", "", "OIDC client ID (otherwise use dynamic registration)")
	flag.Parse()
	if flag.NArg() != 2 {
		flag.Usage()
		os.Exit(2)
	}
	token := os.Getenv("SOLIDFS_TOKEN")
	if (*issuer != "" && token != "") || (*issuer == "" && *clientID != "") {
		fmt.Fprintln(os.Stderr, "-issuer cannot be combined with SOLIDFS_TOKEN; -client-id requires -issuer")
		os.Exit(2)
	}
	pod, err := solidfs.NewPod(flag.Arg(0), token)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if *issuer != "" {
		if err := pod.Authenticate(context.Background(), *issuer, *clientID); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	if _, err := pod.Stat(context.Background(), ""); err != nil {
		fmt.Fprintln(os.Stderr, "access pod:", err)
		os.Exit(1)
	}
	server, err := fs.Mount(flag.Arg(1), solidfs.NewFS(pod), &fs.Options{MountOptions: fuse.MountOptions{Debug: *debug, Name: "solidfs", FsName: "solidfs"}})
	if err != nil {
		fmt.Fprintln(os.Stderr, "mount:", err)
		os.Exit(1)
	}
	server.Wait()
}
