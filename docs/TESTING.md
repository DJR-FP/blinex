# Bline-X Test Plan — Tags/ACLs, Subnets, Exit Nodes

A short manual test plan for the features that depend on a working mesh data
path. Run after deploying v0.10.2+ management and installing v0.10.x agents.

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

> Subnet routing, exit nodes, and ACL enforcement all require **kernel-TUN mode**
> (`blinex-agent status` shows `kernel`). Netstack-mode peers don't run iptables
> and won't enforce or NAT. Put every test device in kernel mode first.

---

## 1. Tags + Access Control Rules

ACLs are deny-by-exception: with no rules, everything is allowed. Adding a
`deny` rule blocks matching traffic; `allow` rules carve out exceptions
(evaluated by priority, lowest number first).

### 1a. Assign tags
1. Dashboard → Devices → on **ubuntu** click **Tags**, add `web`. Save.
2. On **Mentor-Pi02-1** add tag `db`. Save.
3. Dashboard → Access Rules → confirm the **Tag** dropdown now lists `web` and `db`.

✅ Pass: tags appear on the device cards and in the rule editor dropdown.

### 1b. Default allow
- From ubuntu: `ping -c2 100.64.0.3` → **succeeds** (no rules yet).

### 1c. Deny by tag
1. Add a rule: **source** `tag:web`, **destination** `tag:db`, protocol `all`, action **deny**, priority `100`, enabled.
2. Wait ~5s for the agents to sync.
3. From ubuntu (`web`): `ping -c2 100.64.0.3` (`db`) → **fails / 100% loss**.
4. From ubuntu: `ping -c2 100.64.0.2` (untagged) → **still succeeds** (rule only matches web→db).

✅ Pass: only web→db is blocked; other paths unaffected.

### 1d. Allow exception by priority
1. Add a higher-priority rule (lower number): source `tag:web`, dest `tag:db`, protocol `tcp`, port `22`, action **allow**, priority `50`.
2. From ubuntu: `nc -vz 100.64.0.3 22` → **connects** (SSH allowed)…
3. …while `ping -c2 100.64.0.3` (ICMP) → **still blocked** by the deny rule.

✅ Pass: the port-22 allow overrides the broad deny for TCP/22 only.

### 1e. Cleanup
- Delete both rules. Confirm ubuntu can ping 100.64.0.3 again.

> Note: ACLs are enforced on Linux kernel-TUN peers via the `BLINEX-ACL`
> iptables chain. Netstack-mode peers do not enforce ACLs locally.

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

## What to capture if something fails

- Agent: `journalctl -u blinex-agent -n 50 --no-pager`
- iptables (kernel TUN peers): `sudo iptables -S` and `sudo iptables -t nat -S`
- Routes: `ip route` and `ip route get <target>`
- Sync state: `docker compose logs management --tail 30` on the control plane
- Dashboard connection state: does the device still show green?

> Netstack-mode peers (no `/dev/net/tun`) do not enforce ACLs or run iptables
> NAT, so subnet/exit-node advertising and ACL enforcement require kernel TUN.
