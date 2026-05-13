# Rust_VPN

> **Work in progress.** This is a learning project. There is no encryption yet, it runs only on Windows, and the server handles a single client at a time. Do not use it for anything that needs actual privacy or security.

A small UDP tunnel written in Rust that bridges two virtual network interfaces over the network (or loopback). The long-term goal is a proper VPN. For now it's the tunneling layer without crypto.

---

## Status

**Working today**
- UDP tunneling between a client and a server using [Wintun](https://www.wintun.net/) virtual interfaces.
- Two-way packet forwarding on top of Tokio async tasks.
- Per-layer error types (`network`, `packet`, `tun`, future `crypto`) in the `vpn_errors` crate.

**Not yet implemented**
- Encryption and handshake (X25519 plus AEAD on the data path).
- Multi-client support: the server only remembers the most recent client address.
- Linux and macOS: the TUN backend is Wintun-specific.
- Configurable IPs, ports, and adapter names (hardcoded in source for now).
- End-to-end error propagation (`unwrap` and `expect` still on some hot paths).

---

## Project layout

A Cargo workspace with four crates:

| Crate         | Type    | Purpose                                                        |
| ------------- | ------- | -------------------------------------------------------------- |
| `vpn_client`  | binary  | Client endpoint                                                |
| `vpn_server`  | binary  | Server endpoint                                                |
| `vpn_core`    | library | Shared packet parsing, types, and helpers                      |
| `vpn_errors`  | library | Centralized error types (`network`, `packet`, `tun`, `crypto`) |

Hardcoded defaults right now:

|                  | Server             | Client            |
| ---------------- | ------------------ | ----------------- |
| TUN interface IP | `10.0.0.10`        | `10.0.0.9`        |
| TUN adapter name | `MyTun`            | `MyTun`           |
| UDP endpoint     | listens on `12345` | `127.0.0.1:12345` |

---

## Prerequisites

1. **Windows.** The TUN driver is Wintun, so this is Windows-only for now.
2. **Rust toolchain.** Install via [rustup](https://rustup.rs/). Rust 1.74+ recommended.
3. **`wintun.dll`.** Download the Wintun release ZIP from <https://www.wintun.net> and copy the right DLL for your architecture (`bin/amd64/wintun.dll` on most machines) to either:
   - the working directory you're running from, or
   - next to the compiled binary (e.g. `target/debug/vpn_client.exe`).
4. **Administrator privileges.** Both binaries create a virtual network adapter and call `netsh` to configure it. Open your terminal as Administrator before running anything.
5. *(Optional)* **`cargo-make`** if you want the convenience tasks in `Makefile.toml`:
   ```powershell
   cargo install --force cargo-make
   ```

---

## Build

From the workspace root:

```powershell
cargo build
```

For optimized binaries (recommended once you're past the build-it-once stage):

```powershell
cargo build --release
```

---

## Running the project

There are two ways to test, depending on how many machines you have available.

### Scenario A: single machine (loopback)

Useful for a quick sanity check. Both binaries run on the same Windows machine and talk over `127.0.0.1`.

Open two Administrator terminals.

**Terminal 1, server:**
```powershell
cargo run -p vpn_server
```

**Terminal 2, client:**
```powershell
cargo run -p vpn_client
```

Both processes will create their own TUN adapter and start forwarding packets. Open a third Administrator terminal and verify the tunnel:

```powershell
# reach the server's TUN IP through the client interface
ping 10.0.0.10

# reach the client's TUN IP through the server interface
ping 10.0.0.9
```

You should see replies with sub-millisecond latency. This scenario only proves the data path is wired correctly: packets travel through UDP loopback, so it isn't a real network test.

### Scenario B: two machines (LAN or WAN)

This is the real test.

**On the server machine:**

1. Open the UDP port in Windows Firewall:
   ```powershell
   netsh advfirewall firewall add rule name="Rust_VPN_UDP" dir=in action=allow protocol=UDP localport=12345
   ```
2. If the client will reach you across the internet, forward UDP `12345` on your router as well.
3. Confirm `vpn_server/src/main.rs` binds the UDP socket on `0.0.0.0:12345` (not `127.0.0.1:12345`) so it accepts non-loopback traffic. Adjust if needed.
4. Run as Administrator:
   ```powershell
   cargo run -p vpn_server --release
   ```

**On the client machine:**

1. Edit `vpn_client/src/main.rs` and change the server address from `127.0.0.1:12345` to the server's reachable address (its LAN IP or public IP).
2. Build and run as Administrator:
   ```powershell
   cargo run -p vpn_client --release
   ```

Verify from the client machine:
```powershell
ping 10.0.0.10
```

If you get replies, the tunnel is up. Remember that without crypto, anything you send through it travels in cleartext on the wire.

---

## Troubleshooting

- **`Failed to load wintun.dll`:** Wintun couldn't find the DLL. Copy `wintun.dll` next to the binary (e.g. `target/debug/vpn_client.exe`) or into the directory you're running from.
- **`Access is denied` or `netsh` errors:** the terminal isn't elevated. Close it and reopen as Administrator.
- **`Adapter MyTun already exists`:** a previous run left the adapter around. Either re-run (the code will pick it up) or delete it via *Device Manager > Network adapters*.
- **Pings time out.** Most often one of:
  - Windows Firewall is dropping UDP `12345` (see the `netsh advfirewall` rule above).
  - Client is pointing at the wrong server address.
  - One side wasn't launched as Administrator and silently failed to create the adapter.

  Check both processes' output before anything else.

---

## Roadmap

In rough order:

1. **Encryption layer:** X25519 handshake, session keys, ChaCha20-Poly1305 on the data path.
2. **Multi-client server:** replace the single-`SocketAddr` slot with a session map keyed by client identity.
3. **Configuration:** move hardcoded constants (IPs, ports, adapter name, MTU) into a TOML config consumed via `clap` and `serde`.
4. **Cross-platform TUN:** abstract the backend so the `tun` crate (Linux) and `utun` (macOS) also work.
5. **Tighter error handling:** finish the `vpn_errors` rollout so no `unwrap` or `expect` survives on hot paths.

---

## License

TBD.
