# Parallax Core

Reference Golang implementation of the **Parallax protocol**.

> **Parallax** is a Proof-of-Work timechain protocol designed to merge the security model of Bitcoin with the programmability of the EVM. It combines Bitcoin’s fixed monetary rules with Ethereum’s virtual machine to deliver a scarce, decentralized, and programmable timechain.

---

## More on Parallax

- Website: [https://parallaxchain.org](https://parallaxchain.org)
- Technical Documentation: [https://docs.parallaxchain.org](https://docs.parallaxchain.org)
- Whitepaper: [https://parallaxchain.org/introduction/whitepaper](https://parallaxchain.org/introduction/whitepaper)

We have beginner guides on how to run a Parallax node and mining. These can be found [here](https://docs.parallaxchain.org/guides).

---

## Building from Source

Parallax requires **Go 1.25+** and a C compiler.

```bash
make prlx
```

Build the full suite:

```bash
make all
```

---

## Executables

Binaries are located under `build/bin`:

| Command        | Description |
|----------------|-------------|
| **`prlx`** | Main CLI client. Runs full, archive, or light nodes; exposes JSON-RPC over HTTP, WS, and IPC. |
| `clef`         | Stand-alone signer for secure account operations. |
| `devp2p`       | Networking utilities to inspect and interact at the P2P layer. |
| `abigen`       | Generates type-safe Go bindings from contract ABIs. |
| `bootnode`     | Lightweight discovery node to bootstrap networks. |
| `pvm`          | Execute and debug PVM bytecode snippets in isolation. |
| `rlpdump`      | Decode RLP structures into a human-readable form. |

---

## Running a Node

Mainnet (interactive console):

```bash
prlx console
```

Testnet:

```bash
prlx --testnet console
```

### Hardware Recommendations

- **Minimum**: 2 cores, 4 GB RAM, 250 GB SSD, 8 Mbps  
- **Recommended**: 4+ cores, 8 GB RAM, 500 TB SSD, 25+ Mbps

---

## Mining Parallax coins

Parallax miner can be started with:

```
prlx --miner.coinbase <YOUR_WALLET_ADDRESS> --miner.threads 1 --mine
```

You can use your existing web3 wallet address from MetaMask or any other Ethereum based wallet. Or create a new wallet address using either `clef` or `parallaxkey`:

```
parallaxkey generate
```

```
clef newaccount
```

We have beginner guides on how to run a Parallax node and mining. These can be found [here](https://docs.parallaxchain.org/guides).

---

## JSON-RPC (Developers)

IPC is enabled by default. Enable HTTP/WS explicitly:

```
--http --http.addr 0.0.0.0 --http.port 8545 --http.api eth,net,web3
--ws   --ws.addr   0.0.0.0 --ws.port   8546 --ws.api   eth,net,web3
```

> ⚠️ **Security**: Do **not** expose RPC to the public Internet. Use firewalls, auth proxies, and restricted origins.

---

## Contribution

We welcome contributions aligned with **neutrality, openness, and decentralization**.

1. Fork the repo
2. Implement your changes
3. Open a PR against `main`

**Guidelines**

- Format with `gofmt`; document public symbols following Go conventions.  
- Keep commits focused; prefix messages with affected packages (e.g., `prlx, rpc:`).  

---

## License

- **Library code** (`/` excluding `cmd/`): [LGPL v3](https://www.gnu.org/licenses/lgpl-3.0.en.html)  
- **Executables** (`/cmd/*`): [GPL v3](https://www.gnu.org/licenses/gpl-3.0.en.html)

### Attribution Notice

Parallax Core is a derivative work of [go-ethereum](https://github.com/ethereum/go-ethereum) originally developed by the go-ethereum authors and licensed under the GNU LGPL-3.0.
