# thurang

A LAN-only take on Tailscale/Headscale: one machine is the **server** (exit node and/or subnet router), and other machines on the same network **pair with it using a one-time code** and send either selected routes or all of their traffic through it over **WireGuard**.

There's no coordination server: the server node handles pairing and pushes config itself. WireGuard runs in userspace ([boringtun](https://github.com/cloudflare/boringtun)) on a TUN device, so it's one binary on Linux, macOS and Windows with no kernel module or `wg` tools needed.

## Features

- **Exit node:** `thurang up --exit-node` sends all IPv4 traffic through the server. IPv6 goes into the tunnel and is dropped there, so it can't leak around it.
- **Subnet routes:** the server advertises LAN subnets (`--advertise-routes`) and clients opt in with `--accept-routes`.
- **DNS:** the server runs a DNS forwarder on its tunnel IP that sends queries to upstreams you pick (`--dns 1.1.1.1`, a Pi-hole, …). It also answers `<peer>.thurang` names (MagicDNS-style). Clients opt in with `--accept-dns`.
- **OTP pairing:** `thurang otp` on the server prints an 8-digit, single-use code that expires (default 5 min, max 24h). The code goes through SPAKE2, a password-authenticated key exchange, so it never crosses the network and can't be brute-forced offline from captured traffic. Each code allows 5 attempts in total. Pairing swaps WireGuard keys over the resulting encrypted channel.
- **Peer-to-peer:** clients can reach each other by their tunnel IP or name. The server relays the traffic.
- **mDNS discovery:** `thurang join --otp …` finds the server on the LAN without you typing its IP.
- **Clean teardown:** every route, DNS, forwarding and NAT change is written to a journal and undone on exit. If the process crashes, the changes are undone on the next start.

## Quick start

Both sides need root/Administrator. On Windows, put [`wintun.dll`](https://www.wintun.net/) next to `thurang.exe`.

```bash
cargo build --release
```

**Server** (e.g. home server on 192.168.1.10):

```bash
sudo thurang server init --exit-node --dns 1.1.1.1,9.9.9.9 --advertise-routes 192.168.1.0/24
sudo thurang server up            # foreground; run under systemd/launchd/a service for always-on
sudo thurang otp                  # in another terminal -> 4821-0937
```

**Client:**

```bash
sudo thurang join 192.168.1.10 --otp 4821-0937     # or omit the IP to discover via mDNS
sudo thurang daemon &                              # privileged daemon (or use `up --foreground`)
sudo thurang up --exit-node --accept-dns           # all traffic + DNS via server
sudo thurang up --accept-routes                    # or: only advertised subnets
sudo thurang status
sudo thurang down
```

**Managing peers (on the server):** `thurang peers`, `thurang revoke <name>`, `thurang server show`, `thurang server stop`.

**Unpairing / cleanup:** stop the server or client first, then:

```bash
sudo thurang clean            # forget all pairings on this machine (server peers + client pairing)
sudo thurang clean --keys     # ...and delete keys, so old pairings can never reconnect
sudo thurang clean --all      # delete everything, including the server config
```

`clean` asks before deleting anything (pass `--yes` to skip the prompt) and refuses to run while a server or daemon is up. It also undoes any route, DNS or NAT changes left behind by a crash. Ctrl-C on its own only disconnects; pairings stay on disk.

## How it works

| Piece | Where | Transport |
|---|---|---|
| Pairing | server `tcp/51821` | SPAKE2(OTP) → ChaCha20-Poly1305 |
| Data plane | server `udp/51820` | WireGuard (boringtun) ↔ TUN |
| Config push (routes, DNS, exit-node flag) | `100.64.0.1:7001`, inside the tunnel | JSON, authenticated by WireGuard |
| DNS | `100.64.0.1:53`, inside the tunnel | forwarder + `<peer>.thurang` |

The server checks every decrypted packet: a peer can only send from its own tunnel IP, and only to the tunnel subnet, the advertised routes, or anywhere if the server is an exit node. NAT for forwarded traffic is set up per OS:

| | Forwarding | NAT | Client routes | Client DNS |
|---|---|---|---|---|
| Linux | `sysctl ip_forward` | iptables MASQUERADE out any non-tunnel interface (+ MSS clamp) | `ip route` | `resolvectl`, else `/etc/resolv.conf` |
| macOS | `sysctl net.inet.ip.forwarding` | pf anchor `com.apple/thurang` | `route` | `networksetup` (all services) |
| Windows | `netsh … forwarding=enabled` | WinNAT `New-NetNat` | `netsh` routes | interface DNS + NRPT rule |

Exit-node mode adds `0.0.0.0/1` and `128.0.0.0/1` instead of replacing the default route. Directly connected LANs stay local (more specific routes win), and the server's endpoint gets a bypass route when it isn't on-link.

State lives in `/etc/thurang` (Linux), `/Library/Application Support/thurang` (macOS) or `%ProgramData%\thurang` (Windows). Override with `THURANG_HOME`.

## Security model

- **Pairing:** an attacker watching the LAN learns nothing about the code. An active attacker gets 5 online guesses at a 1-in-10⁸ code. Only 4 pairing connections run at once, and an attempt is counted only once a client sends a SPAKE2 message. Because pairing is mutual, a fake server advertised over mDNS can't complete it either.
- **Names:** a newly paired device can't take over another device's name or address: a clashing name gets a `-2` suffix, and `server` is reserved. Re-pairing a device that kept its key keeps its address. `thurang revoke` drops the WireGuard session immediately.
- **Data plane:** WireGuard handshakes go through boringtun's mac1/cookie rate limiter before any DH work is done. The server's endpoint for a peer only changes on authenticated packets. The server enforces each peer's source IP and allowed destinations. A client only accepts packets addressed to its own tunnel IP.
- **Pushed config:** clients reject DNS servers outside the tunnel subnet and a changed subnet, and they ignore advertised `/0` routes.
- **DNS forwarder:** answers tunnel peers only, limits how many queries are in flight, and uses connected sockets for upstream queries so spoofed replies are dropped.
- **Local state:** the state directory must be owned by root/Administrators and not writable by others. On Windows the ACL is reset to SYSTEM + Administrators only. If someone else planted files there, the tool refuses to start, because the undo journal is replayed with full privileges.
- **Known trade-offs:** anyone on the LAN can use up a code's 5 attempts (just issue a new one). An exit node also gives paired clients access to the server's LAN, as with Tailscale. Enabling forwarding on a Linux server makes it a router for its other interfaces too.

## Testing

```bash
cargo test                       # unit tests: OTP, SPAKE2, DNS, policy, route planning, config
cargo build && sudo tests/netns.sh   # Linux end-to-end: pairing, exit node, DNS, cleanup
```

## Limitations / roadmap

- The tunnel carries IPv4 only (IPv6 is blocked in exit-node mode, not tunneled).
- Routes and DNS pushed by the server take effect on the next `thurang up`.
- No `service install` yet. Run `thurang server up` / `thurang daemon` under systemd, launchd or a Windows service wrapper.
- Windows NAT needs WinNAT (Windows 10 / Server 2016+).
