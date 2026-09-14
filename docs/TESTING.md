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

On by default, on every platform the client supports — no setup needed. The
management server fetches a malware/C2 domain feed on a schedule
(`MGMT_BLOCKLIST_URL`, default abuse.ch URLhaus; `MGMT_BLOCKLIST_REFRESH`,
default `6h`); every agent polls for it every 15 minutes and blocks matches
via its Magic DNS resolver (`127.0.0.1:53535`), answering with NXDOMAIN
before the query ever leaves the device. As of v0.17.0, every agent also
points the OS's default DNS route at that resolver itself — the same way
NetBird/Tailscale's MagicDNS does — so this works with a plain `curl`,
`nslookup`, or browser and zero manual DNS configuration, on kernel-TUN
Linux, netstack Linux (unprivileged LXC), and Windows alike. Only macOS
still needs DNS pointed at `127.0.0.1:53535` by hand (no macOS test
environment exists to build/verify against yet).

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
2. **On any peer already on v0.17.0** (any platform), just use the normal
   system resolver — this is the point of §4e's auto-configuration:
   - Linux: `curl <that-domain>` → `Could not resolve host`. `getent hosts
     <that-domain>` → exit code 2, nothing printed.
   - Windows: `nslookup <that-domain>` → `Non-existent domain`.
3. **On a peer still on v0.16.x** (pre-dating auto-configuration), query the
   agent's resolver directly on its own port instead: `dig @127.0.0.1 -p
   53535 <that-domain>`.
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
- Resolve `<some-peer-hostname>.blinex` (via `getent hosts`/`nslookup` on any
  peer already on v0.17.0's auto-configuration, or `dig @127.0.0.1 -p 53535
  ...` on one still manually configured) → still resolves to that peer's
  overlay IP normally. Mesh records are checked before the blocklist and are
  never shadowed by it.

### 4e. Confirm automatic DNS configuration (v0.17.0+)

**Kernel-TUN Linux** (per-link override via `resolvectl`):
1. After the agent starts: `resolvectl status <iface>` (e.g. `blinex0`) →
   `Current Scopes: DNS`, `+DefaultRoute`, `Current DNS Server:
   127.0.0.1:53535`, `DNS Domain: ~.`.
2. `journalctl -u blinex-agent | grep dnsconfig` → a `"dnsconfig: system DNS
   now routed through the agent"` line.
3. **Crash recovery:** `sudo pkill -9 blinex-agent`, then immediately
   `resolvectl status <iface>` → `Failed to resolve interface ... No such
   device` (the non-persistent TUN device died with the process, and
   systemd-resolved dropped the override with it) and `getent hosts
   example.com` still resolves normally — no stuck DNS, nothing to clean up
   by hand. `systemd Restart=on-failure` brings the agent back within a few
   seconds on its own.
4. **Graceful shutdown:** `sudo systemctl stop blinex-agent` → same result,
   `resolvectl status <iface>` shows the link gone and system DNS unaffected.

**Netstack Linux** (unprivileged LXC — global override, UDP relay `:53` →
`:53535`, `/etc/resolv.conf` rewritten):
1. After the agent starts: `cat /etc/resolv.conf` → `nameserver 127.0.0.1`
   with a comment naming the backup path (`/etc/blinex/resolv.conf.bak`).
2. `sudo cat /etc/blinex/resolv.conf.bak` → the real original content (not
   our own override — if this ever shows `nameserver 127.0.0.1` too,
   something backed up its own override instead of the real original, which
   is exactly the bug the "only back up if absent" rule exists to prevent).
3. `journalctl -u blinex-agent | grep dnsconfig` → a `"dnsconfig: system DNS
   now routed through the agent (global override)"` line.
4. **Crash recovery:** `sudo pkill -9 blinex-agent`. Unlike kernel-TUN,
   there's no interface to disappear, so this leans entirely on
   `Restart=on-failure` — confirm `sudo systemctl status blinex-agent` shows
   it back up within a few seconds, `/etc/resolv.conf` still points at
   127.0.0.1 with the *original* backup file untouched, and filtering still
   works (§4b). Note SSH sessions reaching this host over the mesh itself
   will drop when the interface dies and may need a moment (or a retry) to
   reconnect once the new process is up — a transport artifact of testing
   through the very tunnel being torn down, not a sign anything is broken;
   check `journalctl` timestamps if in doubt about what actually happened.
5. **Graceful shutdown:** `sudo systemctl stop blinex-agent` →
   `/etc/resolv.conf` restored to the real original, backup file removed,
   `journalctl` shows `"dnsconfig: restored original /etc/resolv.conf"`
   logged in the same second as the stop request.

**Windows** (global override, UDP relay `:53` → `:53535`,
`Set-DnsClientServerAddress` on every "Up" adapter):
1. After the agent starts: `Get-NetAdapter | Where-Object {$_.Status -eq
   'Up'} | ForEach-Object { Get-DnsClientServerAddress -InterfaceIndex
   $_.InterfaceIndex -AddressFamily IPv4 }` → every active adapter shows
   `127.0.0.1`.
2. `Get-Content $env:ProgramData\blinex\dns-backup.json` → the real original
   per-adapter DNS servers (empty array for an adapter that was on
   DHCP-assigned DNS, explicit IPs for one with static DNS configured).
3. ⚠️ **No crash-recovery safety net today** — see the roadmap. If the
   process is killed uncleanly, every adapter stays pointed at 127.0.0.1
   with nothing listening until someone manually restarts the agent (DNS
   fails safe — queries just fail — but the device won't self-heal the way
   Linux does). Live-tested during v0.17.0's rollout: exactly this happened
   during a routine binary swap and needed a manual console restart.
4. **Graceful shutdown:** stopping the process (Ctrl+C in its console
   window, or killing it cleanly) restores each adapter's original DNS
   servers from the backup file and deletes it.

### Cleanup
- Nothing to revert — filtering and DNS auto-configuration both fully clean
  up after themselves (§4e), whether the agent stops gracefully or crashes.

---

## 5. Windows Service Install (v0.18.0+)

Replaces running the agent as a foreground process in a console window — the
service starts on boot and restarts automatically on a crash, matching
Linux's `systemd Restart=on-failure`, while a deliberate stop is honored
immediately and does not trigger a restart.

> **Defender will very likely remove it on a fresh Windows box first.** An
> unsigned executable that creates a persistent service, rewrites system DNS,
> and binds port 53 matches the behavioral signature Windows Defender uses
> for DNS-hijacking malware — this isn't a theoretical concern, it happened
> live during this feature's own testing (`Get-MpThreatDetection` showed both
> a running v0.17.0 process and, later, the entire v0.18.0 service
> registration detected and removed within seconds of each appearing). For
> testing, exclude the folder first: `Add-MpPreference -ExclusionPath
> "<folder>"`. **Do not treat that as a fix for shipping to real users** — see
> the code-signing item in the README roadmap.

### 5a. Install
1. Elevated PowerShell/cmd (Administrator): `.\blinex-agent.exe install
   -setup-key <key> -management-url <host:50051> -signal-url <host:10000>`.
2. ✅ **Pass:** prints `service installed and started`; `Get-Service
   BlinexAgent` → `Status: Running`, `StartType: Automatic`.
3. Confirm it actually enrolled: check the peer's `version` and `last_seen`
   in the dashboard/API, and re-run the DNS checks from §4b–§4d.

### 5b. Crash recovery
1. Find the running PID: `tasklist | findstr blinex`.
2. `taskkill /PID <pid> /F` — simulates a crash, not a clean stop.
3. ✅ **Pass:** within a few seconds, `Get-Service BlinexAgent` shows
   `Running` again with a **different** PID (`tasklist` again — a restart,
   not the same process surviving), and a fresh `last_seen`/re-enrollment in
   the dashboard. DNS filtering (§4b) should be intact throughout — no
   manual restart needed.

### 5c. Manual stop is honored and does not restart
1. `Stop-Service BlinexAgent` (or `net stop BlinexAgent`).
2. ✅ **Pass:** the service reaches `Stopped` and **stays** stopped — wait
   at least as long as 5b's recovery took and confirm no new PID/re-enrollment
   appears. This is the key difference from 5b: a requested stop must not
   look like a crash to the SCM.
3. Confirm DNS reverted: adapter DNS servers (§4e's Windows check) should be
   back to their original values, not stuck at `127.0.0.1`.
4. `Start-Service BlinexAgent` to bring it back for further testing.

### Cleanup
- `blinex-agent uninstall` (elevated) stops and removes the service. The
  config file at `%ProgramData%\blinex\agent.json` is left in place
  (harmless — reused if you reinstall).

---

## 6. Renaming a Device (v0.19.0+)

### 6a. Rename sticks
1. Dashboard → Devices → click a device's name, edit it, press Enter (or
   click away to save).
2. ✅ **Pass:** the card updates immediately; the `<name>.blinex` shown under
   the IP updates to match.

### 6b. Rename survives an agent restart
- The real point of this feature: restart the renamed device's agent
  (`systemctl restart blinex-agent`, or `Restart-Service BlinexAgent` on
  Windows) and confirm the dashboard still shows the custom name afterward,
  not the device's real OS hostname. A fresh `last_seen` timestamp
  confirms it actually re-enrolled rather than just still being up.

### 6c. Old DNS name stops resolving, new one works — without restarting the *other* peer
1. From a second peer (**not** the one being renamed), confirm the
   pre-rename name resolves: `getent hosts old-name.blinex` (or
   `nslookup old-name.blinex` on Windows).
2. Rename the first device via the dashboard.
3. Wait a few seconds for the sync push, then from that same second peer
   (still running, not restarted): `getent hosts new-name.blinex` → resolves;
   `getent hosts old-name.blinex` → **exit code 2, nothing printed** (Windows:
   `nslookup` reports "Non-existent domain").
4. ✅ **Pass:** the new name resolves and the old one is fully gone, live,
   with no restart needed anywhere. If the old name still resolves, the
   stale-DNS-record bug this feature fixed has regressed.

### Cleanup
- Rename the device back if you don't want the test name to stick.

---

## 7. Windows Kernel-TUN Parity (v0.21.0+)

v0.20.0 gave Windows a real kernel interface via wintun, which flipped
`NetstackMode()` to false — the same flag that used to gate ACL enforcement,
subnet routing and exit-node activation onto Linux-only iptables/netlink code.
v0.21.0 restores all three on Windows: ACLs are filtered in `aclFilterTUN`
(which wraps the wintun device and evaluates policy on every decrypted packet
on its way into the OS), and routing/NAT go through `New-NetRoute` /
`New-NetNat`. These tests confirm a Windows peer is not silently unprotected.

### 7a. ACL enforcement on a Windows peer ✅ *verified 2026-09-09, v0.21.1*
Run from a **second** peer (`SRC`) against the Windows peer's mesh IP (`WIN`).

1. Baseline — with the seeded `Default allow` rule in place, `ping <WIN>` from
   `SRC` succeeds. Pick a third peer as an untouched control and ping it too.
2. Add a rule scoped to the Windows peer alone (rules accept a bare IP or CIDR
   in `src`/`dst`, not just `group:`): priority `100`, src `*`, dst `<WIN>`,
   protocol `all`, action **deny**.
3. Wait ~8s for the sync push, then re-ping.
   ✅ **Pass:** `<WIN>` is **100% blocked** while the control peer still
   answers at 0% loss. If the control also drops, the rule was scoped too
   broadly and the test proves nothing.
4. Delete the rule, wait ~8s, ping again.
   ✅ **Pass:** traffic **fully recovers**. Traffic that stays blocked means a
   stale deny is still installed — the Windows sibling of the Linux stale-rule
   bug (BUG 1) fixed in v0.11.2.

> Use ICMP as the probe: `aclFilterAllows` classifies IP protocol 1 as `icmp`,
> so an `all`-protocol rule covers it. A Windows peer typically has no mesh
> port open to probe with TCP.

### 7b. Watch for a flapping data path first
Before trusting **any** Windows data-path result, confirm the link is stable —
a flapping path produces intermittent loss that reads exactly like an ACL drop:

```bash
journalctl -u blinex-agent --since "5 min ago" | grep -c "stalled, reverted"
```

✅ **Pass:** `0`. A repeating `upgraded from relay` / `stalled, reverted` cycle
means traffic is being thrown onto a direct path that cannot carry it (see the
promotion policy in `client/README.md`). Fixed in v0.21.1; if it reappears,
stop and fix that before interpreting anything else.

### 7z. Windows ↔ Linux parity matrix (as of v0.21.3, 2026-09-14)

Verified live against VirtWin (Win10 Pro 22H2, wintun kernel-TUN) with a Linux
peer. "Verified" means exercised end to end on both platforms in one session,
not inferred from shared code.

| Capability | Linux | Windows | Evidence |
|---|---|---|---|
| Kernel TUN interface | ✅ | ✅ | `blinex0` wintun adapter, mesh route present |
| Magic DNS (mesh names) | ✅ | ✅ | `cloud4.blinex` resolves on both |
| DNS forwarding (public names) | ✅ | ✅ | `google.com` resolves through the agent |
| Malicious-domain blocklist | ✅ | ✅ | same feed version (358 domains), NXDOMAIN on both |
| ACL enforcement, traffic to host | ✅ | ✅ | ICMP-deny rule blocked ping, left SSH working |
| ACL teardown, no stale deny | ✅ | ✅ | removing the rule fully restored ICMP |
| Subnet routing — consumer | ✅ | ✅ | route installed, traffic flows, clean withdrawal |
| Subnet routing — forwarding | ✅ | ✅ | `pktmon` shows the packet leaving the physical NIC |
| Subnet routing — NAT | ✅ | ❌ | **blocked**: WinNAT absent, see §7c |
| Exit node — gateway | ✅ | ⬜ | blocked behind the same NAT gap |
| Exit node — consumer | ✅ | ⬜ | see "exit node is account-wide" below |

**Windows can *use* subnet routes, it just cannot *serve* them.** Verified with
a Linux gateway advertising `10.0.0.0/24`: Windows installed
`blinex0 10.0.0.0/24`, reached both the gateway's own LAN address and a host
beyond it (true transit, ~15 ms), and removed the route cleanly on withdrawal.
Serving is the half that needs NAT; consuming needs only `New-NetRoute`, which
works. Document the limitation as "a Windows peer cannot act as a subnet
router or exit node", not as "subnet routing does not work on Windows".

**Return traffic from a routed subnet needs an explicit ACL rule — on both
platforms.** This is not a Windows quirk. ACL rules expand to *mesh peer IPs*,
so a reply from `10.0.0.1` to a peer's mesh address matches no rule and hits
default-deny. On Windows that is `aclFilterAllows`; on Linux it is the
`BLINEX-ACL` chain, which INPUT jumps to for `-i blinex0` and which has no
conntrack ESTABLISHED accept before its final DROP. The gateway-side capture
showed replies leaving correctly while the consumer silently dropped them;
adding `10.0.0.0/24 → <peer mesh IP> allow` made it work immediately. Until
the ACL model covers return traffic (stateful match, or an implicit allow for
subnets the peer has installed a route for), every subnet-route consumer needs
a hand-written return rule.

**Exit node activation is account-wide, not per-peer.** `engine.go` activates
exit-node routing on *every* peer as soon as *any* peer advertises
`0.0.0.0/0` — there is no per-device opt-in. Enabling one to test it will pull
every other peer's internet traffic through that host. Do not enable one on a
shared account without telling the other peers' owners first. This is also a
product gap worth closing: Tailscale and NetBird both let a device choose
whether to use an available exit node.

**Why the exit-node consumer test is gated.** It installs `0.0.0.0/1` +
`128.0.0.0/1`, moving the default route into the tunnel. If the host-route
pinning in `routing_windows.go` is wrong — the same never-exercised file that
held four bugs before v0.21.3 — the tunnel collapses and takes the only path
to the machine with it. Confirmed live by stopping the agent: with the mesh
down the host was unreachable by every route, so there is no way to diagnose
or recover except a timed watchdog. Do not run it without either a forwarded
SSH port that does not traverse the mesh, or physical access.

**A watchdog is not a substitute.** A scheduled task that restores state after
N minutes (see §7c) makes a failed test survivable, and it earned its place
here — it caught a bad bind address and restored a stopped agent, on the
minute, `lastResult=0`. But it recovers on a timer; it cannot let you look at
a broken box, and it cannot help when the agent itself is what is wedged.

### 7c. Subnet routing / exit node from Windows — ⚠️ PARTIALLY VERIFIED (v0.21.3)
First run live on 2026-09-14 (VirtWin, Win10 Pro 22H2, wintun kernel-TUN,
advertising `192.168.100.0/24` to a Linux consumer). It failed in four silent
ways, all fixed in v0.21.3: `EnableForwarding` was a no-op stub, `New-NetNat`
cannot run at all where `MSFT_NetNat` is unregistered (stock Win10 without
Hyper-V/Containers), the engine logged success regardless, and the ACL filter
default-denied every forwarded packet because it policed transit that Linux
accepts ahead of `BLINEX-ACL`.

**Where it stands:** the consumer installs the route, and the gateway now
genuinely forwards — confirmed with `pktmon` on the gateway, the echo request
leaving on the physical NIC as `100.64.0.9 > 192.168.100.1`. The source is
*not* NATted, so replies do not come back and an end-to-end ping still fails.
To finish this test you need **one** of:

- **WinNAT available on the gateway** — enable the Hyper-V or Containers
  optional feature (needs a reboot), after which `New-NetNat` works and the
  agent NATs mesh traffic onto the LAN; or
- **a static route on the LAN router** — `100.64.0.0/10 via <gateway LAN IP>`,
  which makes NAT unnecessary.

Until one of those is in place the agent logs, correctly, `advertising routes
with forwarding enabled but no NAT`. The exit-node paths below remain
unexercised.

Follow §2 and §3 with the Windows peer as the **gateway**, and check on the
Windows host itself:

```powershell
Get-NetNat                       # masquerade for the advertised subnet
Get-NetRoute -AddressFamily IPv4 # advertised prefixes, exit-node /1 splits
```

> As in §3, when testing the exit-node **consumer** path over a remote session,
> pin a `/32` host route for your client IP via the original gateway first, or
> the default route flips into the tunnel and your session drops.

---

## What to capture if something fails

- Agent: `journalctl -u blinex-agent -n 50 --no-pager`
- iptables (kernel TUN peers): `sudo iptables -S` and `sudo iptables -t nat -S`
- Routes: `ip route` and `ip route get <target>`
- Sync state: `docker compose logs management --tail 30` on the control plane
- Dashboard connection state: does the device still show green?

> Windows peers in kernel (wintun) mode enforce ACLs in userspace too as of
> v0.21.0 — in `aclFilterTUN`, wrapping the tun device rather than through
> Windows Firewall, whose block rules always beat allow rules and so cannot
> express an ordered default-deny chain. See §7.
>
> Netstack-mode peers (no `/dev/net/tun`) enforce ACLs in userspace (v0.14.0+,
> see the callout at the top of this doc) rather than iptables, and act as a
> **subnet router or exit node** (v0.12.0+) via the same userspace gVisor
> forwarder — mesh→LAN / mesh→internet TCP/UDP/ICMP is proxied out through the
> host socket (auto-SNAT), which is how NetBird/Tailscale route through
> containers without a TUN device.
