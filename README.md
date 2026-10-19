# Parallax integration/staging tree

<https://parallaxprotocol.org>

Parallax connects to the Parallax peer-to-peer network to download and fully validate blocks and transactions. It includes a full node, mining engine, and JSON-RPC server.

For an immediately usable, binary version of the Parallax software, see <https://parallaxprotocol.org/en/parallax-client>.

## Building from Source

Parallax requires **Go 1.26+** and a C compiler.

```bash
make parallax
```

This builds the four binaries of the Parallax suite into `build/bin/`:

- **`parallaxd`** — the full-node daemon.
- **`parallax-cli`** — the JSON-RPC command-line client.
- **`parallax-wallet`** — offline wallet management tool (create/list/import accounts, sign messages and raw transactions).
- **`parallax`** — a multi-call wrapper that dispatches to any of the companions.

To build the full suite of tools (adds `clef`, `abigen`, `pvm`, `rlpdump`, `devp2p`):

```bash
make all
```

For detailed build instructions including cross-compilation, Docker builds, and platform-specific notes, see `docs/`.

## Executables

| Command | Description |
|---------|-------------|
| **`parallaxd`** | Full-node daemon. Runs full or archive nodes; serves JSON-RPC over HTTP, WebSocket, and IPC. |
| **`parallax-cli`** | JSON-RPC client with ergonomic sugar subcommands (`info`, `peers`, `balance`, `sendraw`, …). |
| **`parallax-wallet`** | Offline wallet tool. Creates/lists/imports accounts, signs messages and transactions, and produces/restores structured keystore dumps. Never talks to a running node. |
| **`parallax`** | Multi-call wrapper. `parallax node …` → `parallaxd`; `parallax rpc …` → `parallax-cli`; `parallax wallet …` → `parallax-wallet`. |
| `clef` | Long-running external signer daemon with a rule engine and interactive approval UI. Unlike `parallax-wallet`, it's a service that other processes call into over IPC. |
| `devp2p` | Networking utilities to inspect and interact at the P2P layer. |
| `abigen` | Generates type-safe Go bindings from contract ABIs. |
| `pvm` | Execute and debug PVM bytecode in isolation. |
| `rlpdump` | Decode RLP-encoded data into human-readable form. |

## Running a Node

```bash
./build/bin/parallaxd
```

Start with an interactive JavaScript console:

```bash
./build/bin/parallaxd console
```

See the [getting started guide](https://docs.parallaxprotocol.org/parallax-client/getting-started/introduction) for connecting to the network, creating accounts, and sending transactions.

### Daemon mode

Run the node in the background, detached from the terminal:

```bash
./build/bin/parallax-cli start
```

Under the hood, `parallax-cli start` execs the sibling `parallaxd` binary with `--daemon`. `parallaxd` installed next to `parallax-cli` is the default location; `$PATH` is the fallback. Logs redirect to `<datadir>/parallax.log`, a PID file is written, and the process survives terminal exit. See [Daemon mode](https://docs.parallaxprotocol.org/parallax-client/fundamentals/daemon-mode) for systemd integration and flag details.

Invoking `parallaxd --daemon` directly has the same effect.

### Managing a running node

`parallax-cli` is the JSON-RPC client. Common operations have short subcommands that auto-discover the IPC socket in `<datadir>`:

```bash
parallax-cli info           # chain, network, mempool, mining overview
parallax-cli tip            # latest block summary
parallax-cli blockcount     # bare integer, pipeable in shell scripts
parallax-cli balance <addr> # decimal LAX (or --wei for integer)
parallax-cli stop           # graceful shutdown
```

Equivalent invocations through the wrapper:

```bash
parallax rpc info
parallax rpc balance <addr>
```

Object responses are pretty-printed JSON; scalar responses are bare values (safe for `$(parallax-cli blockcount)`). Full reference: [Command-line RPC](https://docs.parallaxprotocol.org/parallax-client/interacting-with-parallax/command-line-rpc).

### Shell completion

Runtime-driven bash and zsh completion scripts ship under `build/completion/`:

```bash
source build/completion/parallaxd.bash
source build/completion/parallax-cli.bash
source build/completion/parallax-wallet.bash
source build/completion/parallax.bash
```

Or install under `~/.local/share/bash-completion/completions/` (bash) or any directory on `$fpath` (zsh) for persistence.

### Docker

Official multi-arch images (amd64/arm64) are published to
[Docker Hub](https://hub.docker.com/r/parallaxprotocol/parallax) on every
release. The entrypoint is the `parallax` multi-call wrapper, so the
familiar subcommands work directly:

```bash
docker run -d --name parallax \
  -v parallax-data:/home/parallax/.parallax \
  -p 32110:32110 -p 32110:32110/udp \
  parallaxprotocol/parallax node

docker exec parallax parallax rpc info   # query it over IPC
docker stop -t 60 parallax               # allow a clean database shutdown
```

The container runs as an unprivileged user (uid 1000) and keeps all
state under `/home/parallax/.parallax` — mount a volume there for
persistence. To serve HTTP RPC, pass `--http --http.addr 0.0.0.0` and
publish port 8545 bound to localhost (`-p 127.0.0.1:8545:8545`); never
expose an unauthenticated RPC port to the public internet. See
[README.docker.md](README.docker.md) for the full reference, or build
the image locally with `docker build -t parallax .`

### Hardware Requirements

| | Minimum | Recommended |
|---|---------|-------------|
| CPU | 1 core | 2+ cores |
| RAM | 2 GB | 4+ GB |
| Storage | 50 GB SSD | 100 GB SSD |
| Network | 1 Mbps | 10+ Mbps |

## Architecture

Parallax uses a layered architecture:

```
kernel/         Consensus rules — no RPC, no networking, no I/O
validation/     Blockchain state, transaction pool, block validation
script/         PVM execution engine, ABI codec
primitives/     Fundamental types (blocks, transactions) and serialization (RLP)
p2p/            Peer-to-peer networking and wire protocol
node/           Node lifecycle, full node, mining
rpc/            JSON-RPC server, GraphQL, typed client
wallet/         Account management, keystore, hardware wallets
```

Each layer only imports from layers below it, enforced by Go's import rules. The `kernel/` package can be embedded independently without pulling in the full node stack.

## Versioning

Parallax releases follow [Semantic Versioning](https://semver.org): `MAJOR.MINOR.PATCH`, tagged as `vX.Y.Z`.

| Component | Bumped for | Example |
|---|---|---|
| **PATCH** (`Z`) | Bug fixes, security patches, performance work. No new features and no interface changes — a drop-in upgrade. | `2.0.0` → `2.0.1` |
| **MINOR** (`Y`) | Features added, changed, or removed: new RPC methods, new CLI flags, new subsystems. Node operators upgrade without changes; removals and behavior changes are listed in the release notes. | `2.0.1` → `2.1.0` |
| **MAJOR** (`X`) | Breaking changes to the exported Go API — moved packages, renamed or removed types and functions. Code that imports Parallax as a library needs edits. `1.x` → `2.0` was the move to the layered architecture above. | `2.1.0` → `3.0.0` |

The major digit tracks the **library** surface, so it matters most to developers embedding `kernel/` or building on the Go packages. For someone who only runs `parallaxd`, a major release mostly means "read the release notes carefully."

Because the major version is part of the Go module path, library consumers pin it in the import path:

```go
import "github.com/ParallaxProtocol/parallax/v2/kernel/chainparams"
```

```bash
go get github.com/ParallaxProtocol/parallax/v2@latest
```

The `/vN` suffix is what lets a `3.x` release land without breaking code still on `2.x` — the two are distinct modules and can coexist in one build.

### Pre-releases and development builds

`version.go` carries the version components plus a metadata tag:

- `unstable` — the development cycle on `main`, e.g. `2.1.0-unstable`. Not a release; the version names the *next* release.
- `rcN` — release candidate, tagged `v2.1.0-rc1`. Any tag containing a hyphen is published as a GitHub pre-release.
- `stable` — the released build. Only stable tags are recommended for mainnet.

Binaries also embed the git commit and build date (`parallaxd version`), so an unstable build is always traceable to a commit.

### Release branches

Each minor series gets a long-lived branch, `X.Y.x` (e.g. `2.0.x`). The series is cut when `X.Y.0` ships; patch releases are tagged from that branch, while `main` moves on to the next minor's development cycle. Documentation is versioned the same way — `docs/v2.0.x`, `docs/v2.1.x` — so the docs for the release you run stay available after newer ones land.

### Consensus is not versioned by releases

The version number describes the *software*, never the *rules*. Parallax treats consensus the way Bitcoin does: the rules are meant to stay fixed. There is no scheduled fork cadence, and a new release is not an occasion to change how blocks are validated. Client releases ship bug fixes, features, and refactors on top of rules that are expected to outlive every version number in this scheme.

Consequently:

- A major version bump means the Go API moved, not that the chain changed. Upgrading from `2.x` to `3.x` does not imply a fork.
- On the rare occasion a consensus change is warranted, it activates at a **block height** in `kernel/chainparams` rather than at a release boundary, and the release carrying it is mandatory for every node regardless of which digit moved.
- The wire protocols carry their own version numbers — `prl/66` for chain sync, `parallax-disc/1` for peer discovery — and bump independently of the release version.

Release notes state explicitly when an upgrade is mandatory rather than optional.

## Development Process

The `main` branch is the development branch. Changes are submitted as pull requests and require review before merging.

### Contributing

1. Fork the repository
2. Create a feature branch
3. Submit a pull request against `main`

Format code with `gofmt`. Document public symbols. Keep commits focused and prefix messages with the affected package (e.g., `kernel/xhash: fix difficulty calculation`).

### Testing

Run the full test suite:

```bash
make test
```

Run the linter:

```bash
make lint
```

Parallax is a security-critical project. Any mistake can cost users money. All changes must include appropriate test coverage and pass CI before merging.

## Resources

- [Technical Documentation](https://docs.parallaxprotocol.org)
- [Beginner Guides](https://docs.parallaxprotocol.org/guides)
- [JSON-RPC API Reference](https://docs.parallaxprotocol.org/parallax-client/interacting-with-parallax/json-rpc-server/overview)
- [Whitepaper](https://parallaxprotocol.org/parallax.pdf)
- [The Parallax Doctrine](https://github.com/ParallaxProtocol/parallax-doctrine)

## License

LGPL-3.0 (library) / GPL-3.0 (executables). See [COPYING](COPYING).
