#!/usr/bin/env bash
# =====================================================================
#  03_persistence.sh - cron / rc.local / startup / systemd / shell-rc
#  review, cron.allow + at.allow lockdown, SSH authorized_keys review
#  and quarantine, SSH AllowUsers.
#  ATT&CK: Persistence (TA0003). Review-first; nothing is deleted -
#  quarantined files are copied to ~root/ccdc/quarantine before removal.
# =====================================================================
[ -n "${BASH_VERSION:-}" ] || { echo "Run with bash: sudo bash $0" >&2; exit 1; }
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh" || { echo "common.sh missing next to $0" >&2; exit 1; }

backdoors() {
    [ -f /etc/rc.local ] && backup_file /etc/rc.local

    echo "User crontabs (review by hand):"
    local f
    for f in /var/spool/cron/crontabs/* /var/spool/cron/* /etc/crontabs/*; do
        [ -f "$f" ] && { echo "--- $f ---"; cat "$f"; backup_file "$f"; }
    done

    echo "System-wide cron locations:"
    ls -la /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly 2>/dev/null

    echo "Pending at jobs:"
    have atq && atq 2>/dev/null

    if [ -f /etc/rc.local ]; then echo "--- /etc/rc.local ---"; grep -Ev '^[[:space:]]*(#|$)' /etc/rc.local; fi

    echo "Listening ports right now:"
    list_listening
    log "Backdoor/cron review complete, see above output"
}

CCDC_PERSIST_PATTERN='/dev/(tcp|udp)/|nc(at)? .*-e|bash -i|sh -i|mkfifo|socat .*exec|python[0-9.]* -c|perl -e|(curl|wget) [^|]*\|[[:space:]]*(ba)?sh|base64 -d|/tmp/|/dev/shm/|/var/tmp/|chmod \+s|LD_PRELOAD'

persistence_pattern_scan() {
    local ts report days=${CCDC_RECENT_DAYS:-7} f h
    ts=$(date +%Y%m%d_%H%M%S)
    report=$CCDC_INVENTORY/persistence_scan_$ts.txt
    echo "Scanning common persistence locations for reverse-shell/dropper patterns..."
    {
        echo "=== Suspicious patterns in cron / rc.local / profile / shell rc / systemd units ==="
        local targets=(/etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly
                       /var/spool/cron /etc/crontabs /etc/rc.local /etc/rc.d/rc.local /etc/profile /etc/profile.d
                       /etc/bash.bashrc /etc/bashrc /etc/environment /etc/systemd/system /lib/systemd/system
                       /usr/lib/systemd/system /etc/init.d /etc/update-motd.d /etc/xdg/autostart)
        while IFS=: read -r _ _ _ _ _ h _; do
            for f in .bashrc .bash_profile .profile .bash_logout .zshrc .config/autostart; do
                [ -e "$h/$f" ] && targets+=("$h/$f")
            done
        done < /etc/passwd
        grep -rIEn "$CCDC_PERSIST_PATTERN" ${targets[@]+"${targets[@]}"} 2>/dev/null | grep -v "ccdc_watchdog\|ccdc_reassert" | head -n 300

        echo; echo "=== /etc/ld.so.preload (should normally not exist) ==="
        if [ -s /etc/ld.so.preload ]; then cat /etc/ld.so.preload; else echo "absent/empty (good)"; fi

        echo; echo "=== systemd units with ExecStart in temp/world-writable paths ==="
        grep -rIEn '^[[:space:]]*Exec(Start|StartPre|StartPost|Reload|Stop)=.*(/tmp/|/dev/shm/|/var/tmp/|/home/)' \
            /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null

        echo; echo "=== Unit files / init scripts / cron files modified in the last $days days ==="
        find /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system /etc/init.d /etc/cron.d \
             /etc/cron.hourly /etc/cron.daily /var/spool/cron /etc/profile.d -xdev -type f -mtime "-$days" 2>/dev/null \
            | while read -r f; do ls -l "$f"; done

        echo; echo "=== Timers (systemd) ==="
        have systemctl && systemctl list-timers --all --no-pager 2>/dev/null | head -n 40

        echo; echo "=== Immutable files in common persistence paths (red team uses chattr +i) ==="
        have lsattr && lsattr -R /etc/cron.d /etc/ssh /root/.ssh /etc/systemd/system 2>/dev/null | awk '$1 ~ /i/'
    } > "$report"
    cat "$report"
    log "Persistence pattern scan written: $report"
}

cron_at_lockdown() {
    local allow_users="root ${CCDC_CRON_ALLOW_USERS:-}" f
    echo "Current user crontabs exist for:"
    ls -1 /var/spool/cron/crontabs /var/spool/cron /etc/crontabs 2>/dev/null | grep -Ev '^(/|$|crontabs$)' | sort -u | sed 's/^/  /'
    if ! ask "Restrict cron and at to: ${allow_users} (writes /etc/cron.allow + /etc/at.allow)?" CCDC_CRON_LOCKDOWN no; then
        log "cron/at lockdown skipped"
        return 0
    fi
    for f in /etc/cron.allow /etc/at.allow /etc/cron.deny /etc/at.deny; do backup_file "$f"; done
    printf '%s\n' $allow_users | sort -u > /etc/cron.allow
    printf '%s\n' $allow_users | sort -u > /etc/at.allow
    chmod 600 /etc/cron.allow /etc/at.allow
    chown root:root /etc/cron.allow /etc/at.allow
    log "cron.allow / at.allow now: $(tr '\n' ' ' < /etc/cron.allow). Undo: restore from $CCDC_BACKUPS"
}

_authkeys_files() {
    local user h f extra b p
    while IFS=: read -r user _ _ _ _ h _; do
        for f in "$h/.ssh/authorized_keys" "$h/.ssh/authorized_keys2"; do
            [ -f "$f" ] && echo "$user:$f"
        done
    done < /etc/passwd
    # custom AuthorizedKeysFile locations (%u / %h tokens)
    if b=$(sshd_bin); then
        extra=$("$b" -T 2>/dev/null | awk '$1=="authorizedkeysfile" {for(i=2;i<=NF;i++) print $i}')
        for f in $extra; do
            case $f in *%u*|*%h*|*%%*)
                while IFS=: read -r user _ _ _ _ h _; do
                    p=${f//%u/$user}; p=${p//%h/$h}; [ "${p:0:1}" = / ] || p=$h/$p
                    [ -f "$p" ] && echo "$user:$p"
                done < /etc/passwd ;;
            /*) [ -f "$f" ] && echo "?:$f" ;;
            esac
        done
    fi
}

ssh_authkeys_review() {
    local have_list=0 entry user f n mode qmode=${CCDC_QUARANTINE_AUTHKEYS:-none}
    load_users >/dev/null 2>&1 && have_list=1
    echo "SSH authorized_keys files on this box:"
    local seen=""
    while IFS= read -r entry; do
        user=${entry%%:*}; f=${entry#*:}
        case " $seen " in *" $f "*) continue ;; esac
        seen="$seen $f"
        n=$(grep -cEv '^[[:space:]]*(#|$)' "$f" 2>/dev/null)
        mode=$(stat -c '%a %U' "$f" 2>/dev/null)
        local flag=""
        [ "$user" = root ] && flag="ROOT "
        [ "$have_list" = 1 ] && [ "$user" != root ] && [ "$user" != "?" ] && ! is_authorized "$user" && flag="${flag}UNAUTHORIZED-USER "
        echo "--- $f  (user=$user, $n keys, perms=$mode) ${flag:+<< $flag}"
        if have ssh-keygen; then
            ssh-keygen -lf "$f" 2>/dev/null | sed 's/^/    /'
        else
            awk '!/^[[:space:]]*(#|$)/ {print "    " $1 " ... " $NF}' "$f"
        fi
        local quarantine=no
        if ccdc_noninteractive; then
            case $qmode in
                all) quarantine=yes ;;
                unauthorized) [[ $flag == *UNAUTHORIZED* ]] && quarantine=yes ;;
            esac
        else
            ask "  Quarantine $f (copy to $CCDC_QUARANTINE, then remove)?" && quarantine=yes
        fi
        if [ "$quarantine" = yes ]; then
            have chattr && chattr -i -a "$f" 2>/dev/null
            local dest=$CCDC_QUARANTINE/authorized_keys/$(echo "$f" | tr '/' '_')
            mkdir -p "$CCDC_QUARANTINE/authorized_keys"
            cp -a "$f" "$dest" && rm -f "$f" && log "Quarantined $f -> $dest (restore: cp -a '$dest' '$f')"
        fi
    done < <(_authkeys_files)
    [ -z "$seen" ] && echo "  none found"
}

ssh_effective_config_review() {
    local b
    b=$(sshd_bin) || { echo "sshd not installed."; return 0; }
    echo "Effective sshd settings that matter (sshd -T):"
    "$b" -T 2>/dev/null | grep -Ei '^(permitrootlogin|passwordauthentication|pubkeyauthentication|permitemptypasswords|authorizedkeysfile|authorizedkeyscommand|allowusers|allowgroups|denyusers|port|listenaddress|x11forwarding|gatewayports|permittunnel) ' | sed 's/^/  /'
    echo "Match blocks in sshd config (can silently override the above per user/host):"
    grep -rniE '^[[:space:]]*Match[[:space:]]' "$SSHD_CONF" /etc/ssh/sshd_config.d 2>/dev/null | sed 's/^/  /' || true
}

ssh_allowusers() {
    [ -f "$SSHD_CONF" ] || { echo "No sshd_config."; return 0; }
    load_users || { warn "Skipping AllowUsers: no authorized user list."; return 1; }
    local list=() u
    for u in "${authorized[@]}"; do id "$u" >/dev/null 2>&1 && list+=("$u"); done
    if [ -n "${SUDO_USER:-}" ] && ! in_list "$SUDO_USER" ${list[@]+"${list[@]}"}; then
        list+=("$SUDO_USER")
        warn "Adding you ($SUDO_USER) to AllowUsers so you are not locked out"
    fi
    [ ${#list[@]} -gt 0 ] || { warn "No existing authorized users - not writing AllowUsers"; return 1; }
    echo "Proposed: AllowUsers ${list[*]}"
    echo "Check: the scoring engine's SSH account MUST be in this list or SSH scoring will fail."
    ask "Write AllowUsers to sshd_config (validated with sshd -t, rolled back on error)?" CCDC_SSH_ALLOWUSERS no || return 0
    sshd_begin_change || return 1
    sshd_set AllowUsers "${list[*]}"
    sshd_commit_change && log "AllowUsers set: ${list[*]}"
}

persistence_auto() {
    backdoors
    persistence_pattern_scan
    cron_at_lockdown
    ssh_effective_config_review
    ssh_authkeys_review
    ssh_allowusers || true
    return 0
}

persistence_actions() {
    cat <<'EOF'
  auto        all of the below
  review      cron / rc.local / at / listening ports review (read-only)
  scan        reverse-shell/dropper pattern scan across persistence locations
  cron        cron.allow + at.allow lockdown
  sshconfig   effective sshd settings + Match blocks (read-only)
  authkeys    authorized_keys review + quarantine
  allowusers  SSH AllowUsers from the authorized list
EOF
}

persistence_run_action() {
    case $1 in
        auto) persistence_auto ;;
        review) backdoors ;;
        scan) persistence_pattern_scan ;;
        cron) cron_at_lockdown ;;
        sshconfig) ssh_effective_config_review ;;
        authkeys) ssh_authkeys_review ;;
        allowusers) ssh_allowusers ;;
        *) err "Unknown action: $1"; persistence_actions; return 2 ;;
    esac
}

persistence_menu() {
    ccdc_menu "03_persistence.sh - Persistence" \
        "Run all" persistence_auto \
        "Backdoor/cron/startup review (read-only)" backdoors \
        "Persistence pattern scan (reverse shells, droppers, systemd)" persistence_pattern_scan \
        "cron.allow / at.allow lockdown" cron_at_lockdown \
        "Effective sshd config + Match blocks" ssh_effective_config_review \
        "authorized_keys review + quarantine" ssh_authkeys_review \
        "SSH AllowUsers" ssh_allowusers
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    ccdc_main persistence "$@"
fi
