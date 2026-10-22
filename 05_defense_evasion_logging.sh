#!/usr/bin/env bash
# =====================================================================
#  05_defense_evasion_logging.sh - keep logs from being rotated/wiped
#  away, flag history/log tampering, checksum baseline of critical
#  files (checked every 2 min by the watchdog), optional auditd rules.
#  ATT&CK: Defense Evasion (TA0005).
# =====================================================================
[ -n "${BASH_VERSION:-}" ] || { echo "Run with bash: sudo bash $0" >&2; exit 1; }
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh" || { echo "common.sh missing next to $0" >&2; exit 1; }

INTEGRITY_BASELINE_NAME=integrity_baseline.sha256
INTEGRITY_DIRLIST_NAME=integrity_dirlist.txt

log_retention() {
    log "Log retention / protection"
    if [ "$INIT_SYS" = systemd ] && [ -f /etc/systemd/journald.conf ]; then
        if ask "Make the systemd journal persistent (survives reboot / journald restart)?" CCDC_JOURNAL_PERSISTENT yes; then
            backup_file /etc/systemd/journald.conf
            mkdir -p /var/log/journal
            have systemd-tmpfiles && systemd-tmpfiles --create --prefix /var/log/journal >/dev/null 2>&1
            set_line /etc/systemd/journald.conf Storage "=" persistent
            systemctl restart systemd-journald 2>/dev/null && log "journald Storage=persistent"
        fi
    fi

    local svc
    for svc in rsyslog syslog-ng syslog; do
        if svc_exists "$svc"; then
            svc_is_active "$svc" || { svc_enable_now "$svc" && log "Started $svc (was not running)"; }
            break
        fi
    done

    # keep more rotations so a forced rotate can't push evidence out
    if [ -f /etc/logrotate.conf ]; then
        local cur keep=${CCDC_LOGROTATE_KEEP:-12}
        cur=$(awk '/^[[:space:]]*rotate[[:space:]]+[0-9]+/ {print $2; exit}' /etc/logrotate.conf)
        if [ -z "$cur" ] || [ "$cur" -lt "$keep" ]; then
            backup_file /etc/logrotate.conf
            set_line /etc/logrotate.conf rotate " " "$keep"
            log "logrotate global rotate ${cur:-unset} -> $keep"
        fi
    fi

    local f
    find /var/log -xdev -type f -perm -0002 2>/dev/null | while read -r f; do
        chmod o-w "$f" && log "Removed world-write from log $f"
    done

    echo "Key auth/session logs (empty or missing = possible tampering):"
    for f in /var/log/auth.log /var/log/secure /var/log/messages /var/log/syslog /var/log/wtmp /var/log/btmp /var/log/lastlog; do
        if [ -e "$f" ]; then
            if [ -s "$f" ]; then printf '  %-22s %s\n' "$f" "$(du -h "$f" 2>/dev/null | cut -f1)"
            else printf '  %-22s EMPTY  <-- check\n' "$f"; fi
        fi
    done
}

history_tamper_check() {
    echo "Shell-history / logging suppression (classic defense evasion):"
    local files=(/etc/profile /etc/bash.bashrc /etc/bashrc /etc/environment) h found=0
    [ -d /etc/profile.d ] && files+=(/etc/profile.d/*)
    while IFS=: read -r _ _ _ _ _ h _; do
        files+=("$h/.bashrc" "$h/.bash_profile" "$h/.profile" "$h/.zshrc")
    done < /etc/passwd
    local hits
    hits=$(grep -HnE 'HISTFILE=/dev/null|unset[[:space:]]+HISTFILE|HISTSIZE=0|HISTFILESIZE=0|set \+o history' \
        "${files[@]}" 2>/dev/null)
    [ -n "$hits" ] && { echo "$hits" | sed 's/^/  /'; found=1; }
    while IFS=: read -r _ _ _ _ _ h _; do
        [ -L "$h/.bash_history" ] && { echo "  $h/.bash_history is a symlink -> $(readlink "$h/.bash_history")"; found=1; }
    done < /etc/passwd
    [ "$found" = 0 ] && echo "  none found"

    echo "/etc/ld.so.preload:"
    if [ -s /etc/ld.so.preload ]; then sed 's/^/  /' /etc/ld.so.preload; warn "/etc/ld.so.preload is populated - classic userland rootkit hook"; else echo "  absent/empty (good)"; fi
}

_sha_cmd() {
    if have sha256sum; then echo sha256sum
    elif have shasum; then echo "shasum -a 256"
    else return 1
    fi
}

_integrity_targets() {
    local p b
    local paths=(/etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/sudoers /etc/sudoers.d/*
                 /etc/ssh/sshd_config /etc/ssh/sshd_config.d/* /etc/pam.d/* /etc/crontab /etc/cron.d/*
                 /etc/rc.local /etc/ld.so.preload /etc/profile /etc/profile.d/* /etc/bash.bashrc /etc/bashrc
                 /etc/hosts /etc/resolv.conf /etc/nsswitch.conf /etc/systemd/system/*.service
                 /root/.ssh/authorized_keys /root/.bashrc /etc/cron.allow /etc/at.allow)
    for b in sshd sudo su login passwd ps ss netstat ls find bash sh crontab systemctl; do
        p=$(command -v "$b" 2>/dev/null) && paths+=("$(readlink -f "$p")")
    done
    if [ -n "${CCDC_INTEGRITY_EXTRA:-}" ]; then
        # shellcheck disable=SC2206
        paths+=($CCDC_INTEGRITY_EXTRA)
    fi
    for p in "${paths[@]}"; do [ -f "$p" ] && echo "$p"; done | sort -u
}

_integrity_dirs() { echo "/etc/cron.d /etc/systemd/system /etc/profile.d /etc/sudoers.d /etc/ssh/sshd_config.d /etc/init.d /root/.ssh /usr/local/bin /usr/local/sbin"; }

integrity_baseline() {
    local sha out dl d
    sha=$(_sha_cmd) || { warn "No sha256sum/shasum - cannot build integrity baseline"; return 1; }
    out=$CCDC_STATE/$INTEGRITY_BASELINE_NAME
    dl=$CCDC_STATE/$INTEGRITY_DIRLIST_NAME
    [ -f "$out" ] && cp -a "$out" "$CCDC_BACKUPS/${INTEGRITY_BASELINE_NAME}.$(date +%Y%m%d_%H%M%S)"
    _integrity_targets | while read -r f; do $sha "$f"; done > "$out" 2>/dev/null
    for d in $(_integrity_dirs); do [ -d "$d" ] && find "$d" -maxdepth 1 -type f 2>/dev/null; done | sort > "$dl"
    cp -a "$out" "$CCDC_BACKUPS/" 2>/dev/null
    rm -f "$CCDC_STATE/integrity_last_alert.txt"
    log "Integrity baseline: $(wc -l < "$out") files -> $out (re-run after any intentional change)"
}

integrity_check() {
    local sha out dl d changes
    sha=$(_sha_cmd) || { warn "No sha256sum/shasum"; return 1; }
    out=$CCDC_STATE/$INTEGRITY_BASELINE_NAME
    dl=$CCDC_STATE/$INTEGRITY_DIRLIST_NAME
    [ -f "$out" ] || { echo "No baseline yet - run: sudo bash 05_defense_evasion_logging.sh --run baseline"; return 1; }
    changes=$($sha -c "$out" 2>/dev/null | grep -v ': OK$')
    local newfiles
    newfiles=$(for d in $(_integrity_dirs); do [ -d "$d" ] && find "$d" -maxdepth 1 -type f 2>/dev/null; done | sort | comm -13 "$dl" - 2>/dev/null)
    if [ -z "$changes" ] && [ -z "$newfiles" ]; then
        echo "Integrity check: no changes since baseline."
        return 0
    fi
    [ -n "$changes" ] && { echo "CHANGED/MISSING since baseline:"; echo "$changes" | sed 's/^/  /'; }
    [ -n "$newfiles" ] && { echo "NEW files in watched dirs:"; echo "$newfiles" | sed 's/^/  /'; }
    log "Integrity check found changes (see output)"
    return 3
}

auditd_rules() {
    if ! have auditctl; then
        local p=audit
        [ "$PKG" = apt ] && p=auditd
        ask "auditd is not installed. Install $p for file-watch/recon auditing?" CCDC_INSTALL_AUDITD no || return 0
        pkg_install "$p" || return 1
        svc_enable_now auditd
    fi
    local rules=/etc/audit/rules.d/ccdc.rules w
    mkdir -p /etc/audit/rules.d
    backup_file "$rules"
    {
        echo "# CCDC toolkit watches - search with: ausearch -k ccdc_identity (etc)"
        for w in /etc/passwd /etc/shadow /etc/group /etc/gshadow; do [ -e "$w" ] && echo "-w $w -p wa -k ccdc_identity"; done
        for w in /etc/sudoers /etc/sudoers.d; do [ -e "$w" ] && echo "-w $w -p wa -k ccdc_priv"; done
        for w in /etc/ssh/sshd_config /etc/ssh/sshd_config.d /root/.ssh; do [ -e "$w" ] && echo "-w $w -p wa -k ccdc_ssh"; done
        for w in /etc/crontab /etc/cron.d /var/spool/cron /etc/systemd/system /etc/rc.local; do [ -e "$w" ] && echo "-w $w -p wa -k ccdc_persist"; done
        echo "-w /etc/ld.so.preload -p wa -k ccdc_preload"
        for w in whoami id; do
            w=$(command -v "$w" 2>/dev/null) && echo "-w $(readlink -f "$w") -p x -k ccdc_recon"
        done
    } > "$rules"
    if have augenrules; then augenrules --load >/dev/null 2>&1; else auditctl -R "$rules" >/dev/null 2>&1; fi
    log "auditd rules loaded from $rules (keys: ccdc_identity ccdc_priv ccdc_ssh ccdc_persist ccdc_preload ccdc_recon)"
}

defense_evasion_auto() {
    log_retention
    history_tamper_check
    auditd_rules
    integrity_baseline
    return 0
}

defense_evasion_actions() {
    cat <<'EOF'
  auto        log retention -> history/preload tamper check -> auditd rules -> integrity baseline
  logs        log retention / protection
  tamper      shell-history suppression + ld.so.preload check
  auditd      auditd watch rules (installs auditd only if confirmed)
  baseline    (re)build integrity baseline of critical files
  check       compare critical files against the baseline (exit 3 = changes)
EOF
}

defense_evasion_run_action() {
    case $1 in
        auto) defense_evasion_auto ;;
        logs) log_retention ;;
        tamper) history_tamper_check ;;
        auditd) auditd_rules ;;
        baseline) integrity_baseline ;;
        check) integrity_check ;;
        *) err "Unknown action: $1"; defense_evasion_actions; return 2 ;;
    esac
}

defense_evasion_menu() {
    ccdc_menu "05_defense_evasion_logging.sh - Defense Evasion / Logging" \
        "Run all" defense_evasion_auto \
        "Log retention / protection" log_retention \
        "History / ld.so.preload tamper check" history_tamper_check \
        "auditd watch rules" auditd_rules \
        "(Re)build integrity baseline" integrity_baseline \
        "Integrity check against baseline" integrity_check
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    ccdc_main defense_evasion "$@"
fi
