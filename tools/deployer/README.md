# Agbero deployer

Local build-and-deploy helper. It cross-compiles Agbero, uploads the binary over
SSH, atomically replaces the remote binary, detects a systemd service or a
manual process, restarts where safe, health-checks, and rolls back on failure.

It is intentionally a `tools/` program, not an `agbero` subcommand.

## Usage

```bash
make deploy PLAY_HOST=host.example
make deploy PLAY_HOST=host.example TEST=1
make deploy PLAY_HOST=host.example MODE=install
make deploy PLAY_HOST=host.example MODE=service
```

`MODE` values:

- `auto` — update when a binary exists, otherwise fresh install (interactive
  mode selection when a TTY is available)
- `update`
- `install`
- `service` — install/repair the systemd unit and restart; does not replace the
  binary

`TEST=1` runs `go test ./...` before building. Tests are off by
default so an in-progress failing test does not block an intentional deploy.

`YES=1` skips confirmations. Extra flags can be passed with `DEPLOY_ARGS`.

## Version

No manual version flag. The tool uses:

```bash
git describe --tags --always --dirty
git rev-parse --short HEAD
```

and injects them into `woos.Version`, `woos.Commit`, and `woos.Date`.

## Requirements

- Local Go toolchain
- SSH access to the target as root (or a root-capable SSH alias)
- `ssh`, `scp`, and a POSIX shell on the target
- systemd for automatic service restart

The server does not need Go or the source tree.

## Safety

- Builds with `CGO_ENABLED=0`.
- Uploads to `.agbero.new` in the same directory as the target.
- Verifies SHA-256 on the server.
- Keeps `agbero.prev`.
- Restarts only a detected service.
- Warns instead of killing a manually-started process.
- Rolls back when restart or health fails.
