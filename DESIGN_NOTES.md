# DESIGN_NOTES — CCDC Linux toolkit split

This file records the judgment calls the master prompt didn't decide, and every place where behavior differs from `ccdc_master.sh` (and why). The goal was "restructure and document, not redesign". So any change in behavior is listed here. Most of them fix a bug in the original that would have taken a scored service down or locked a human out.

---

## 1. Judgment calls

| Decision | Choice | Reasoning |
|---|---|---|
| Non-interactive config format | `ccdc.conf` with `KEY=value` lines, **parsed, not sourced**. Only `CCDC_*`/`NEED_*` keys are read. Env vars override the file. Search order: `$CCDC_CONF`, `./ccdc.conf`, toolkit dir, `/etc/ccdc/ccdc.conf`. | A sourced config is code that runs as root. A parsed one can't execute anything. Env-overrides-file lets centralized tooling tweak one value per host. |
| What switches non-interactive mode | `--auto` / `-y` / `--non-interactive`, or `CCDC_NONINTERACTIVE=yes` | The prompt said interactive must remain the default when no config is supplied. A config file sitting next to the scripts should not silently turn off prompts, so it needs the explicit key. |
| Defaults for unanswered questions | Anything that can drop a scored service or lock out a human defaults to **no**. Pure attack-surface reductions with no realistic uptime cost default to **yes**. | Uptime is scored. The full list is in `ccdc.conf.example`. |
| The "mandatory pause" in non-interactive mode | Staging writes the CSV. With a TTY, the orchestrator waits for Enter on `/dev/tty`. With no TTY it **exits 3** and prints `--auto --from 01` to resume. | This satisfies both "zero prompts other than the mandatory pause" and "stops and exits with a clear message rather than ever auto-applying". A headless run can't silently skip the pause. |
| If nothing is staged | No CSV, no pause, the run continues (same as the original `write_pcr_csv` early return). | Teams that rotate credentials another way can still run unattended end to end. |
| Applying staged passwords | `passwords.sh --run apply` (interactive "yes"), or headless `--run apply --confirm-pcr-submitted`. That flag is **ignored if put in ccdc.conf**. The orchestrator never passes it. | It has to be a separate, explicit, human-triggered invocation, and config on disk must never be able to apply passwords. |
| Staged passwords persist | `~root/ccdc/staging/pending_passwords.csv` (mode 600). The original kept them in memory only. | Once the script is split, staging and applying are different invocations. The queue has to survive the exit. `staging/` already existed in the original but was unused. |
| Re-staging protection | In `--auto`, a user who is already staged is **kept**, not given a new password. Interactive mode asks before replacing. | Otherwise re-running could replace a password that is already on a submitted PCR, and the applied password would differ from the one orange team has. |
| Where the toolkit writes | `<root's home>/ccdc` (from `/etc/passwd`), override `CCDC_HOME` | Under sudo, `~` can be the operator's home. Under cron it is root's. The original's watchdog could log somewhere different from the scripts. |
| `script.log` | Appended with a per-run header (the original truncated it). | It is the "document changes as you go" record across 13 scripts. Truncating it erased history. |
| One home per function | `enumerate_nmap`/`hunt_local_ports` live in `enumeration.sh`, and `07` sources it. Firewall save/reload lives in `08`, and `09` sources it. The integrity baseline lives in `05`, and `10` sources it. `lock_account`, `fw_signature`, sshd helpers and the README→unit map are in `common.sh` because several scripts need them. | This is what the prompt asked for ("have the other script source it"). Every script uses a `BASH_SOURCE` guard, so sourcing never triggers a menu. |
| Ingress/egress split for nftables | Two tables: `inet ccdc` (08) and `inet ccdc_egress` (09). | A packet must pass every base chain on a hook, so together they equal the original single table. Either half can be re-run or reverted without wiping the other. |
| ufw ingress re-run after egress | 08 does `ufw --force reset` as before, then replays 09's saved rules (`state/ufw_egress_rules`) if egress was applied. | ufw has one ruleset. A reset would otherwise silently drop egress. |
| Orchestrator menu | Original options 1–20 kept with the same numbers and meaning. **21** opens any script's own menu. Option 8 "User auditing" now calls the split halves (`rogue_accounts` + `lock_root`/`uid0_check`/`admin_group_reconcile`). | Muscle memory survives. New capabilities stay reachable. |
| Run Everything (menu 1) | Same priority order as `--auto`, prompting as it goes. Password staging now happens inside it (second), not as a separate later option. | The prompt moved `passwords.sh` to second place. Applying still never happens. |
| Playbook | `CCDC_Playbook_Minute0_to_Hour6.md` was **not produced**: a safety classifier stopped generation of that document. | See the session summary. |
| `06_` numbering | There is no `06_` file. Credential Access is `passwords.sh`, as instructed. | Plain names for the two scripts people grab first. |

---

## 2. Behavior changes from `ccdc_master.sh` (bug fixes and safety rails)

**Uptime breakers fixed**
- **Firewall reload helper looped forever.** `write_firewall_reload_helper` copied the whole interactive menu script into `/usr/local/sbin/ccdc_firewall_reload.sh`. When cron ran it with no input, `read` hit EOF and the menu looped forever, starting a new copy every 2 minutes. The helper is now generated: it restores the saved ruleset with no prompts, using `nft -f` on a file that starts with `flush ruleset`, so the swap is atomic.
- **README services were blocked by the firewall.** The nft branch only opened 53 outbound on a DNS server, so DNS service was blocked. No backend opened Samba (139/445, 137/138 udp). Mail ingress existed only in nft. All backends now open every README-needed service. DB ports open only if you confirm remote clients (`CCDC_MYSQL_REMOTE` / `CCDC_POSTGRES_REMOTE`).
- **Egress baseline differed by backend.** nft blocked outbound DNS unless the box was a DNS server, which broke package installs. iptables had no NTP. All four backends now use tcp 53/80/443 + udp 53/123 (+25/587 for mail).
- **Apache 2.4 configtest failed.** The original rewrote `Options Indexes FollowSymLinks` to `Options -Indexes FollowSymLinks`, which Apache 2.4 rejects (no mixing `+/-` with bare options). The scored web service went down. The `Indexes` word is now removed instead. Every service hardening step is now snapshotted, validated (`apachectl -t`, `testparm`, `named-checkconf`, `proftpd -t`, `sshd -t`) and **rolled back automatically** if validation fails or the service doesn't come back.
- **vsftpd refused to start or refused logins.** `ssl_enable=YES` without a certificate stops vsftpd from starting, so it is now only set when `rsa_cert_file` exists. `chroot_local_user=YES` makes vsftpd 3 reject users with a writable home, so `allow_writeable_chroot=YES` is added. The RHEL path `/etc/vsftpd/vsftpd.conf` is handled.
- **BIND was restarted even when `named-checkconf` failed.** It is now rolled back instead.
- **sshd settings could land inside a `Match` block.** Settings appended at the end of `sshd_config` take effect only inside a trailing `Match` block (or fail validation). On Ubuntu 22.04+, `sshd_config.d/*.conf` files override the main file. Both are handled, and validation with rollback was added.
- **sudoers cleanup could remove someone's only sudo grant.** `sed '/NOPASSWD/d'` deleted whole grant lines (e.g. `ubuntu ALL=(ALL) NOPASSWD:ALL`). Now only the tag is stripped. On `visudo -c` failure, `sudoers.d` is restored too, not just `/etc/sudoers`. The step refuses if the operator has no usable password.
- **`/etc/shadow` permissions.** `chown root:root` broke `unix_chkpwd` on Debian, so the `shadow` group is kept there. `chmod 640` loosened RHEL's `000`. Permissions are now only ever tightened.
- **Forwarding hosts.** `ip_forward=0` and FORWARD DROP cut off Docker/Podman/LXC/libvirt guests. When the host forwards traffic or runs containers you are asked first, and the default is to keep forwarding (and keep existing nft tables) in `--auto`.

**Lockout safety rails (new)**
- If you're on SSH and the README says no ssh, TCP 22 stays open (`CCDC_KEEP_SSH_FOR_ADMIN`). Disabling root SSH login while logged in directly as root asks first.
- `$SUDO_USER` is never locked, staged, removed from admin groups, or left out of `AllowUsers`.
- An empty authorized-user list aborts instead of marking every account unauthorized.
- Root's password is only locked automatically when you came in through sudo.

**Stronger, not weaker**
- Locking also expires the account (`usermod -L -e 1`). A password lock alone still allows SSH-key login. The undo command is logged.
- `gen_password` re-rolls until it has all four character classes. About 30% of plain random draws lacked a symbol and violated `ocredit=-1`.
- The PCR CSV is mode 600 and CSV-quoted.
- The watchdog re-asserts the firewall if it is **modified**, not just flushed (cksum of the CCDC rules). It keeps a copy of tampered rules, detects service flapping, checks file integrity, uses a lock to stop the two cron entries from overlapping, uses absolute paths, and keeps its port snapshots in `state/` instead of world-writable `/tmp`.
- Dropped packets are logged (rate-limited, `CCDC-IN-DROP` / `CCDC-OUT-DROP`), so there are dropped packets to watch.
- Pristine backups are never overwritten. The pre-change firewall ruleset is saved for every backend.
- `bad_packages` covers RHEL/Arch package names and pacman/apk, and asks once before removing.
- The media sweep offers quarantine before the irreversible delete, and deletes exactly the scanned list.

**Cosmetic**
- The UDP report was labelled "top 50" but scanned top 100. It is now labelled `udp_top100`.

---

## 3. New functionality (where the prompt asked for it)
- **05** (log retention, history/preload tamper checks, sha256 integrity baseline + check, optional auditd) — the prompt asked for this explicitly.
- **03**: cron.allow/at.allow lockdown, authorized_keys review/quarantine, AllowUsers. The prompt said these were "currently inside the original", but they weren't, so they were written.
- **09**: outbound watchlist hunt, plus a pre-check that lists live outbound dependencies the egress lockdown would break.
- **07**: IOC hunt from WinterKnight's list, and the contain → eradicate → recover responder.
- **enumeration.sh**: dependency map ("Finding the Monkey") and an accounts snapshot.
- **01**: README-driven "stop services you don't need" (stop + disable, never uninstall; sshd never auto-disabled).

Not built, as the prompt directed: honeypots, deception, canary tokens; forensics or chain-of-custody workflow.

---

## 4. Self-check

**Section 5 non-negotiables**

| # | Requirement | Status |
|---|---|---|
| 1 | Passwords never applied by staging, under any flag or mode | ✅ No code path in `stage`/`auto`/orchestrator calls `chpasswd`. Apply needs an interactive yes or a CLI-only flag. Tested. |
| 2 | 2-minute watchdog: restart, firewall re-assert, port diff, crontab + `/etc/cron.d` | ✅ `10_impact_monitoring.sh` |
| 3 | Default-deny both directions, nft → ufw → firewalld → iptables, pre-change ruleset saved | ✅ 08 + 09, `fw_backup_pre` for every backend |
| 4 | Runs on apt/dnf/yum/zypper/pacman/apk; clear messages; keeps going | ✅ Detects, warns, continues. Requires bash ≥ 4. BusyBox fallbacks for `usermod`/`gpasswd`/`ps`/`ss`. ⚠️ See testing limits. |
| 5 | Backups before changes, incl. runtime dirs; never delete evidence | ✅ `backup_file` everywhere a file changes; 01 snapshots runtime dirs; quarantine is copy-then-remove |
| 6 | Lock, don't delete | ✅ |
| 7 | Non-interactive mode for every script + orchestrator | ✅ `--auto`, `ccdc.conf`, env |
| 8 | Media sweep separate, never in default or auto paths, scan-then-confirm | ✅ Only reachable via menu 19 or by name. `--auto` scans only. |
| 9 | Watchlists defined once, shared | ✅ `common.sh` |
| 10 | Each script standalone, no hidden order dependencies | ✅ Each creates `~root/ccdc` if missing (with a note). 09 warns if 08 wasn't run. 10 warns if no reload helper exists. 05 `check` says when there is no baseline. |

**Section 2 capability list**: every item has a home (see "Split layout" in `ccdc_script_reference_notes.txt`). None were dropped.

---

## 5. Testing performed and limits

- `bash -n` on every script. `shellcheck -S warning` is clean.
- A 66-case unit test run on bash 5.3 with GNU sed and both gawk and mawk. It covered config parsing and precedence, `ask` defaults, `set_line` edge cases, sshd Match-block insertion, Apache `Indexes` rewrite, sudoers rewrite, permission tightening, password generation, PCR CSV contents and permissions, apply gating, re-stage protection, README answer caching, the generated watchdog/reassert/reload scripts, orchestrator order, `--from` / `--only`, and the exit-3 halt when there is no TTY.
- **Not done:** the scripts were written and unit-tested on macOS. They have **not** been run end-to-end on real Debian/Ubuntu, RHEL/Rocky, openSUSE, Arch or Alpine boxes, or against live nftables/ufw/firewalld/iptables. Before competition day, run each script once on a snapshot VM of every distro you expect (a short, single-subteam practice mock is the right place). In particular, check:
  1. `08`/`09` on each firewall backend, from a second host.
  2. That the watchdog's firewall signature stays stable across two runs. `tail ~root/ccdc/logs/watchdog.log` should show no repeated "FIREWALL CHANGED".
  3. Apache/vsftpd rollback, by feeding a broken config.
