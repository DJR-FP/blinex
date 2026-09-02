# Bline-X Test Plan — Groups/ACLs, Subnets, Exit Nodes, Domain Filtering

A short manual test plan for the features that depend on a working mesh data
path. Run after deploying v0.10.2+ management and installing v0.10.x agents.

> **Automated tests (v0.11.1+).** The control plane and agent now ship a unit /
> integration suite — run `go test ./...` in each module (`management`, `signal`,
> `client`). It covers JWT auth & revocation, IPAM, login rate limiting, the
> stores, REST authorization/IDOR, signal routing & peer-identity enforcement,
> DNS resolution, peer diffing, and the relay/ICE data-path link. The manual
> steps below complement it by exercising the parts that need real kernel TUN,
> iptables, and multi-host traffic (which the unit suite cannot).

**Reference setup** (adjust IPs to your mesh):

| Host | Mesh IP | Mode |
|------|---------|------|
| ubuntu | 100.64.0.1 | kernel TUN |
| netmesh-client | 100.64.0.2 | kernel TUN (after `/dev/net/tun` passthrough) |
| Mentor-Pi02-1 | 100.64.0.3 | kernel TUN |

**Baseline before starting:** all three can ping each other, and the dashboard
shows all three with green dots ("3 of 3 connected").

**Pre-flight on each device (v0.11.0+ CLI):**

```bash
blinex-agent status     # confirm version, mesh IP, "kernel mode", peer/route counts
blinex-agent peers      # confirm all other peers are listed, note direct vs relay
blinex-agent routes     # confirm route advertisements propagated (used in §2/§3)
```

> **ACL enforcement (v0.14.0+)** works in **both modes**: kernel-TUN peers
> enforce via the `BLINEX-ACL` iptables chain; netstack-mode peers (unprivileged
> LXC, Windows, macOS) enforce the identical policy in userspace via
> `aclAllows`, for both traffic they forward (subnet-router/exit-node) *and*
> connections addressed to their own overlay IP. **Subnet routing and exit
> nodes also work in either mode:** kernel peers forward + `MASQUERADE` via
> iptables, while netstack peers act as a **userspace subnet router / exit
> node** (v0.12.0+) — the gVisor netstack forwards mesh→LAN (or
> mesh→internet) TCP/UDP/ICMP out through the host socket (auto-SNAT, no
> iptables).
>
> **Default policy is deny (v0.15.0+).** With zero rules, nothing can reach
> anything — not even two devices in the same group. A fresh account is seeded
> with one `group:Default → group:Default, allow` rule so an out-of-box mesh
> isn't cut off (every device is always in `Default`, regardless of enrollment
> path). §1 below exercises that seeded rule directly — delete it as part of
> 1e and you'll see the mesh go fully silent, which is expected.

---

## 1. Groups + Access Control Rules

Groups replace what used to be called tags. Every device is always in
`Default`; setup keys can drop a newly-enrolled device straight into
additional groups on top of it. ACL rules match `group:<name>`, evaluated in
priority order (lowest number first), first match wins, **default deny**.

### 1a. Assign groups
1. Dashboard → Devices → on **ubuntu** click **Groups**, add `web`. Save.
2. On **Mentor-Pi02-1** add group `db`. Save.
3. Dashboard → Access Rules → confirm the **Group** dropdown now lists `web` and `db`
   (alongside `Default`, which every device already has).

✅ Pass: groups appear on the device cards and in the rule editor dropdown.

### 1b. Seeded default-allow
- From ubuntu: `ping -c2 100.64.0.3` → **succeeds** — not because of an implicit
  default-allow, but because both devices are in `Default` and the seeded
  `Default → Default` rule permits it. Confirm it in Access Rules: a rule
  named "Default allow", priority 1000, still enabled.

> **Test-tooling note:** if a device is netstack-mode, ICMP won't transparently
> route the way TCP does (`iptables REDIRECT`, which the local-process
> forwarder relies on, doesn't cover ICMP) — a plain `ping` from *inside* a
> netstack host can show as blocked/unreachable even when the ACL itself
> allows it. Use a real TCP connection (e.g. `nc -vz` or, more reliably since
> some `nc` builds report success prematurely on a connection a deny rule
> actually drops, a genuine SSH attempt) as the ground truth instead.

### 1c. Deny by group
1. Add a rule: **source** `group:web`, **destination** `group:db`, protocol `all`, action **deny**, priority `100`, enabled. (Lower number than the seeded 1000, so it's evaluated first.)
2. Wait ~5s for the agents to sync.
3. From ubuntu (`web`): `ping -c2 100.64.0.3` (`db`) → **fails / 100% loss**.
4. From ubuntu: `ping -c2 100.64.0.2` (in `Default` only) → **still succeeds** (rule only matches web→db; `Default → Default` still applies).

✅ Pass: only web→db is blocked; other paths unaffected.

### 1d. Allow exception by priority
1. Add a higher-priority rule (lower number): source `group:web`, dest `group:db`, protocol `tcp`, port `22`, action **allow**, priority `50`.
2. From ubuntu: a real SSH attempt to `100.64.0.3:22` → **reaches the SSH handshake** (allowed)…
3. …while `ping -c2 100.64.0.3` (ICMP) → **still blocked** by the deny rule.

✅ Pass: the port-22 allow overrides the broad deny for TCP/22 only.

### 1e. Cleanup
- Delete both rules. Confirm ubuntu can ping 100.64.0.3 again (back to the
  seeded `Default → Default` allow).
- To see default-deny with nothing softening it, also delete the seeded
  "Default allow" rule and confirm ubuntu can no longer reach 100.64.0.3 at
  all — then re-create it (`group:Default → group:Default`, `all`, allow,
  priority 1000) to restore the starting state.

---

## 2. Subnet Routing

Make one peer advertise a LAN subnet so other peers can reach hosts behind it.

**Setup:** pick a peer with a real LAN behind it (e.g. Mentor-Pi02-1 on
`192.168.1.0/24` with another device at `192.168.1.50`).

**Advertise (on the gateway — Mentor-Pi02-1):**
1. Dashboard → Devices → **Mentor-Pi02-1** → **Routes** → add subnet `192.168.1.0/24`. Save.
2. The card shows a `192.168.1.0/24` badge.
3. On Mentor-Pi02-1: `blinex-agent routes` → the row shows `192.168.1.0/24  this device  yes`.
4. Confirm forwarding + NAT came up automatically:
   - `cat /proc/sys/net/ipv4/ip_forward` → `1`
   - `sudo iptables -t nat -S POSTROUTING | grep MASQUERADE` → a `100.64.0.0/10 … MASQUERADE` rule.

**Consume (on another peer — ubuntu):**
5. Wait ~5s for sync. `blinex-agent routes` on ubuntu → shows `192.168.1.0/24  mentor-pi02-1  yes`.
6. `ip route get 192.168.1.50` → routes via `blinex0`.
7. `ping -c2 192.168.1.50` → **succeeds** (reaches the LAN host behind the gateway).
8. Optional: `traceroute 192.168.1.50` → first hop is the gateway's mesh IP (100.64.0.3).

✅ **Pass:** ubuntu reaches a LAN host behind Mentor-Pi02-1 by its real IP; both
agents stay green in the dashboard.

❌ **If it fails, capture:** `blinex-agent routes` on both; `ip route get 192.168.1.50`;
`sudo iptables -t nat -S` and `cat /proc/sys/net/ipv4/ip_forward` on the gateway.

### Cleanup
- Remove the `192.168.1.0/24` route. Confirm `ip route get 192.168.1.50` no
  longer uses `blinex0` and `blinex-agent routes` no longer lists it.

---

## 3. Exit Node

Route a peer's **default** internet traffic through another mesh peer.

**Setup:** make ubuntu an exit node; route Mentor-Pi02-1's traffic through it.

**Advertise (on the exit — ubuntu):**
1. Dashboard → Devices → **ubuntu** → **Routes** → toggle **Exit node** on (advertises `0.0.0.0/0`). Save. Card shows an **Exit node** badge.
2. `blinex-agent routes` on ubuntu → shows `0.0.0.0/0  this device  yes`.
3. Confirm forwarding/NAT (as in §2): `ip_forward=1`, MASQUERADE rule present.

**Consume (on Mentor-Pi02-1):**
4. Before switching: `curl -s https://api.ipify.org` → note its current public IP.
5. Enable ubuntu as the exit/gateway for Mentor-Pi02-1 (dashboard route selection).
6. Wait ~5s. `blinex-agent routes` on Mentor-Pi02-1 → shows `0.0.0.0/0  ubuntu`.
7. `curl -s https://api.ipify.org` → now returns **ubuntu's public IP**.
8. Control-plane safety: `blinex-agent status` still shows the mesh IP and peers,
   and the dashboard keeps the device green — the agent pins a host route to the
   management/signal server via the original gateway so it doesn't cut itself off.

✅ **Pass:** Mentor-Pi02-1's egress IP becomes ubuntu's; the agent stays connected
to the control plane (no disconnect/reconnect loop).

❌ **If it fails, capture:** `journalctl -u blinex-agent -n 50` on Mentor-Pi02-1
(look for the exit-node host-route lines); `ip route` before/after; whether the
device drops to grey in the dashboard.

### Cleanup
- Turn off the exit node. Confirm `curl https://api.ipify.org` from
  Mentor-Pi02-1 returns its own public IP again and `ip route` is restored.

---

## 4. Domain Filtering (v0.16.0+) and Automatic Magic DNS (v0.17.0+)

On by default — no setup needed on **Linux kernel-TUN peers**. The management
server fetches a malware/C2 domain feed on a schedule (`MGMT_BLOCKLIST_URL`,
default abuse.ch URLhaus; `MGMT_BLOCKLIST_REFRESH`, default `6h`); every agent
polls for it every 15 minutes and blocks matches via its Magic DNS resolver
(`127.0.0.1:53535`), answering with NXDOMAIN before the query ever leaves the
device. As of v0.17.0, a kernel-TUN Linux agent also points the OS's default
DNS route at that resolver itself (via `resolvectl`), so this works with a
plain `curl`/browser and zero manual DNS configuration — the same way
NetBird/Tailscale's MagicDNS does. **Netstack peers (Windows, macOS,
unprivileged LXC) and Windows generally don't have this yet** — see §4e —
so on those you still need to query the resolver directly on its own port.

### 4a. Confirm the server compiled a feed
1. `docker compose logs management | grep blocklist` → a `"blocklist: feed
   updated"` line with a nonzero `domains` count. If MGMT_BLOCKLIST_URL was
   left at its default, this happens within a few seconds of the management
   server starting (the first fetch is synchronous, not on the 6h timer).

### 4b. Confirm an agent picked it up and blocks a known-bad domain
1. Pick a domain currently listed in the feed you configured (check the feed
   content directly, e.g. `curl -s https://urlhaus.abuse.ch/downloads/hostfile/
   | grep -m1 '^127\.0\.0\.1'` — feed contents rotate, so there's no fixed
   domain to hardcode here).
2. **On a kernel-TUN Linux peer already on v0.17.0**, just use the normal
   system resolver — this is the point of §4e's auto-configuration:
   `curl <that-domain>` → `Could not resolve host`. `getent hosts
   <that-domain>` → exit code 2, nothing printed.
3. **On any other peer** (netstack, Windows, or a kernel-TUN peer still on
   v0.16.x), query the agent's resolver directly on its own port instead:
   `dig @127.0.0.1 -p 53535 <that-domain>` (or `nslookup <that-domain>
   127.0.0.1 -port=53535` on Windows/older `dig`-less systems).
4. ✅ **Pass:** `NXDOMAIN` / `status: NXDOMAIN` (or curl's "Could not resolve
   host"), no answer.
5. Confirm an unrelated, definitely-not-malicious domain still resolves
   normally through the same path — filtering should not be blocking traffic
   generally, only feed matches.

### 4c. Confirm subdomain coverage
- Query a random subdomain of the same blocked domain from §4b (e.g.
  `made-up-label.<blocked-domain>`) → also NXDOMAIN/unresolvable. Blocking a
  domain blocks everything under it.

### 4d. Confirm mesh (Magic DNS) resolution is unaffected
- Resolve `<some-peer-hostname>.blinex` (via `getent hosts` on an auto-
  configured kernel-TUN peer, or `dig @127.0.0.1 -p 53535 ...` elsewhere) →
  still resolves to that peer's overlay IP normally. Mesh records are checked
  before the blocklist and are never shadowed by it.

### 4e. Confirm automatic DNS configuration (kernel-TUN Linux only, v0.17.0+)
1. On a kernel-TUN Linux peer, after the agent starts:
   `resolvectl status <iface>` (e.g. `blinex0`) → `Current Scopes: DNS`,
   `+DefaultRoute`, `Current DNS Server: 127.0.0.1:53535`, `DNS Domain: ~.`.
2. `journalctl -u blinex-agent | grep dnsconfig` → a `"dnsconfig: system DNS
   now routed through the agent"` line.
3. **Crash recovery:** `sudo pkill -9 blinex-agent`, then immediately
   `resolvectl status <iface>` → `Failed to resolve interface ... No such
   device` (the non-persistent TUN device died with the process, and
   systemd-resolved dropped the override with it) and `getent hosts
   example.com` still resolves normally — no stuck DNS, nothing to clean up
   by hand. Restart the agent afterward.
4. **Graceful shutdown:** `sudo systemctl stop blinex-agent` → same result,
   `resolvectl status <iface>` shows the link gone and system DNS unaffected.

### Cleanup
- Nothing to revert — filtering and DNS auto-configuration both fully clean
  up after themselves (§4e), whether the agent stops gracefully or crashes.

---

## What to capture if something fails

- Agent: `journalctl -u blinex-agent -n 50 --no-pager`
- iptables (kernel TUN peers): `sudo iptables -S` and `sudo iptables -t nat -S`
- Routes: `ip route` and `ip route get <target>`
- Sync state: `docker compose logs management --tail 30` on the control plane
- Dashboard connection state: does the device still show green?

> Netstack-mode peers (no `/dev/net/tun`) enforce ACLs in userspace (v0.14.0+,
> see the callout at the top of this doc) rather than iptables, and act as a
> **subnet router or exit node** (v0.12.0+) via the same userspace gVisor
> forwarder — mesh→LAN / mesh→internet TCP/UDP/ICMP is proxied out through the
> host socket (auto-SNAT), which is how NetBird/Tailscale route through
> containers without a TUN device.
