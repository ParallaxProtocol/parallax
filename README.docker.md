# Parallax

Official Docker images for [Parallax](https://github.com/ParallaxProtocol/parallax),
a peer-to-peer electronic cash system with 10-minute proof-of-work blocks
and smart contract support. Each image bundles the full client suite:
`parallaxd` (the node daemon), `parallax-cli` (the JSON-RPC client),
`parallax-wallet` (the offline wallet tool) and the `parallax` multi-call
wrapper, which is the image entrypoint.

Images are published for `linux/amd64` and `linux/arm64` with SBOM and
provenance attestations.

## Tags

- `latest` - most recent stable release
- `2.0`, `2.0.0` - specific release lines
- Prerelease tags (e.g. `2.0.0-rc3`) are published but never move `latest`

## Quick start

Run a full node with persistent chain data:

```bash
docker run -d --name parallax \
  -v parallax-data:/home/parallax/.parallax \
  -p 32110:32110 -p 32110:32110/udp \
  parallaxprotocol/parallax node
```

Follow the logs:

```bash
docker logs -f parallax
```

Query the running node through the bundled RPC client (uses the IPC
socket inside the container, no HTTP setup needed):

```bash
docker exec parallax parallax rpc info
docker exec parallax parallax rpc blockcount
```

Stop gracefully. Give the database time to close cleanly rather than
accepting Docker's 10-second default kill:

```bash
docker stop -t 60 parallax
```

## Ports

| Port | Protocol | Purpose |
|------|----------|---------|
| 32110 | TCP + UDP | P2P networking and node discovery |
| 8545 | TCP | JSON-RPC over HTTP (opt-in, off by default) |
| 8546 | TCP | JSON-RPC over WebSocket (opt-in, off by default) |

## Enabling HTTP RPC

The HTTP server binds to localhost inside the container by default, so a
published port stays unreachable until you bind it to the container's
external interface:

```bash
docker run -d --name parallax \
  -v parallax-data:/home/parallax/.parallax \
  -p 32110:32110 -p 32110:32110/udp \
  -p 127.0.0.1:8545:8545 \
  parallaxprotocol/parallax node --http --http.addr 0.0.0.0
```

**Warning:** `--http.addr 0.0.0.0` trusts Docker's network boundary to do
the filtering. Publish the port bound to `127.0.0.1` (as above) or keep
it inside a private Docker network; never expose an unauthenticated RPC
port to the public internet.

## Volumes

- `/home/parallax/.parallax` - chain data, keystore, IPC socket, logs.
  Declared as a volume; mount a named volume or host path here.
- `/home/parallax/.xhash` - XHash mining DAGs. Only worth mounting when
  mining; DAGs are regenerated if absent.

The container runs as the unprivileged user `parallax` (uid/gid 1000).
When bind-mounting a host directory, make sure uid 1000 can write to it.

## Wrapper subcommands

The entrypoint is the `parallax` multi-call wrapper:

```bash
docker run --rm parallaxprotocol/parallax version        # print version info
docker run --rm parallaxprotocol/parallax node --help    # parallaxd flags
docker run --rm parallaxprotocol/parallax rpc --help     # parallax-cli commands
docker run --rm parallaxprotocol/parallax wallet --help  # offline wallet tool
```

## Resources

- [Source repository](https://github.com/ParallaxProtocol/parallax)
- [Documentation](https://docs.parallaxprotocol.org)
- [JSON-RPC API reference](https://docs.parallaxprotocol.org/client/interacting-with-parallax/json-rpc-server/overview)

## License

LGPL-3.0 (library) / GPL-3.0 (executables).
