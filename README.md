# solidfs

`solidfs` mounts a Solid container as a FUSE filesystem. Containers appear as directories and resources as files.

## Build and run

Requires Go 1.27 or newer, Linux with FUSE, and `fusermount3`.

```sh
go build -o build/solidfs ./cmd/solidfs
mkdir -p mountpoint
./build/solidfs https://example.org/my-pod/ mountpoint
```

The process stays in the foreground. In another terminal, unmount with `fusermount3 -u mountpoint`.

The command is in `cmd/solidfs`; the reusable Pod client, authentication, and FUSE filesystem are in `pkg/solidfs`.

By default requests are anonymous. If the server accepts a bearer token, supply it in `SOLIDFS_TOKEN` (use HTTPS to protect it):

```sh
export SOLIDFS_TOKEN='your-access-token'
./build/solidfs https://example.org/my-pod/ mountpoint
```

For interactive Solid-OIDC login, supply your identity provider's issuer URL:

```sh
./build/solidfs -issuer https://identity.example/ https://example.org/my-pod/ mountpoint
```

Open the printed URL in a browser on the same machine and complete login. The provider redirects to a temporary loopback listener. By default the client attempts dynamic registration; alternatively pass `-client-id CLIENT_ID` for a public client registered to allow loopback redirects with a variable port. The provider must support authorization code flow with PKCE, DPoP access tokens, and `openid webid offline_access` scopes. ID tokens signed with RS256 or ES256 are supported. The issuer and Pod must use HTTPS (loopback HTTP issuers are permitted for development). Some Solid providers use different registration or token-exchange flows and may not be compatible.

The DPoP key and tokens are held in memory only; login is required again after restarting. Refresh tokens, when issued, are used automatically. `SOLIDFS_TOKEN` cannot be combined with `-issuer`; static bearer tokens are not refreshed. Do not use a real bearer token over HTTP.

## Semantics and limitations

- Supports listing, reading, creating, writing, truncating and deleting files, and creating and deleting directories. Containers must return Turtle and support standard Solid HTTP operations.
- Writes read and upload whole resources synchronously, so large files are expensive. Updates are not protected against concurrent writers; an upload can overwrite remote changes. This is not a POSIX filesystem and should not be used for concurrent editing or critical data without backups.
- Rename, links, POSIX ownership, permissions and timestamp changes are not supported. Directory metadata and access modes do not represent the Pod's authorization policy. HTTP redirects are not followed.
- No offline operation or cache coherence guarantees are provided. Pod access policies can prevent individual operations even when the mount succeeds.
