#!/usr/bin/env bash
# =====================================================================
#  04_privilege_escalation.sh - root lockout, UID-0 anomalies, admin
#  group reconciliation, sudoers cleanup, sensitive file permissions.
#  ATT&CK: Privilege Escalation (TA0004).
# =====================================================================
[ -n "${BASH_VERSION:-}" ] || { echo "Run with bash: sudo bash $0" >&2; exit 1; }
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh" || { echo "common.sh missing next to $0" >&2; exit 1; }

lock_root() {
    if [ -z "${SUDO_USER:-}" ]; then
        warn "You are logged in directly as root (no SUDO_USER). Locking root's password may lock you out of console/su."
        ask "Lock root's password anyway?" CCDC_LOCK_ROOT no || { log "Root lock skipped"; return 0; }
    fi
    backup_file /etc/shadow
    passwd -l root >/dev/null 2>&1 && log "Root account locked for direct password login (sudo still works). Undo: passwd -u root"
}

uid0_check() {
    echo "Users with UID 0 (should ONLY be root):"
    local u rogue=()
    while read -r u; do
        echo "  $u" | tee -a "$LOG"
        [ "$u" != root ] && rogue+=("$u")
    done < <(awk -F: '$3 == 0 {print $1}' /etc/passwd)
    if [ ${#rogue[@]} -gt 0 ]; then
        warn "Extra UID-0 accounts: ${rogue[*]}"
        backup_file /etc/passwd /etc/shadow
        for u in "${rogue[@]}"; do
            ask "Lock UID-0 account '$u' (not delete)?" CCDC_LOCK_UID0_ROGUES yes && lock_account "$u"
        done
    fi
    echo "Accounts with GID 0 as primary group (review):"
    awk -F: '$4 == 0 && $1 != "root" {print "  " $1}' /etc/passwd
}

_group_members() { awk -F: -v g="$1" '$1==g {gsub(",", " ", $4); print $4}' /etc/group; }
_group_add() { if have gpasswd; then gpasswd -a "$1" "$2" >/dev/null 2>&1; else addgroup "$1" "$2" >/dev/null 2>&1; fi; }
_group_del() { if have gpasswd; then gpasswd -d "$1" "$2" >/dev/null 2>&1; else delgroup "$1" "$2" >/dev/null 2>&1; fi; }

admin_group_reconcile() {
    load_users || { warn "Skipping admin reconciliation: no authorized user list."; return 1; }
    backup_file /etc/group /etc/gshadow
    local admin_group="sudo" user g m
    grep -q "^wheel:" /etc/group && admin_group="wheel"
    grep -q "^${admin_group}:" /etc/group || { warn "No sudo/wheel group on this box"; return 1; }

    for user in "${authorized[@]}"; do
        id "$user" >/dev/null 2>&1 || continue
        if is_admin "$user"; then
            _group_add "$user" "$admin_group"
            log "$user confirmed as admin ($admin_group)"
        elif [ "$user" = "${SUDO_USER:-}" ]; then
            warn "$user (you) is not in the admin list - NOT removing your own sudo."
        else
            _group_del "$user" "$admin_group"
            log "$user is a standard user"
        fi
    done

    for g in sudo wheel admin; do
        for m in $(_group_members "$g"); do
            is_admin "$m" && continue
            is_authorized "$m" && continue
            [ "$m" = "${SUDO_USER:-}" ] && { warn "$m (you) is in $g but not on the admin list - leaving it"; continue; }
            if ask "$m is in admin group '$g' but is not an authorized admin. Remove from $g?" CCDC_REMOVE_NONADMIN_FROM_SUDO yes; then
                _group_del "$m" "$g" && log "Removed $m from $g"
            fi
        done
    done

    echo "Users whose PRIMARY group is an admin group (gpasswd can't remove these - review):"
    for g in sudo wheel admin; do
        local gid
        gid=$(awk -F: -v g="$g" '$1==g {print $3}' /etc/group)
        [ -n "$gid" ] && awk -F: -v gid="$gid" -v g="$g" '$4==gid {print "  " $1 " (" g ")"}' /etc/passwd
    done
}

sudoers_grant_review() {
    echo "Active sudoers grants (review anything not for root/%sudo/%wheel/%admin or a listed admin):"
    grep -HnEv '^[[:space:]]*(#|$|Defaults)' /etc/sudoers /etc/sudoers.d/* 2>/dev/null | sed 's/^/  /'
}

sudoers_stuff() {
    [ -f /etc/sudoers ] || { echo "No /etc/sudoers - skipping."; return 0; }
    if [ -n "${SUDO_USER:-}" ]; then
        local hash
        hash=$(awk -F: -v u="$SUDO_USER" '$1==u {print $2}' /etc/shadow 2>/dev/null)
        case $hash in
            ''|'!'*|'*'*)
                warn "$SUDO_USER has no usable password. After NOPASSWD is removed you will NOT be able to sudo."
                warn "Set one first:  passwd $SUDO_USER"
                ask "Continue with sudoers cleanup anyway?" CCDC_SUDOERS_FORCE no || return 1 ;;
        esac
    fi
    local snap f
    snap=$(mktemp -d "$CCDC_STATE/sudoers_snap.XXXXXX") || return 1
    cp -a /etc/sudoers "$snap/sudoers"
    [ -d /etc/sudoers.d ] && cp -a /etc/sudoers.d "$snap/sudoers.d"
    backup_file /etc/sudoers /etc/sudoers.d/*

    echo "Lines that will change:"
    grep -HnE 'NOPASSWD|!authenticate' /etc/sudoers /etc/sudoers.d/* 2>/dev/null | sed 's/^/  /'

    # strip the NOPASSWD tag (keeps the grant, requires a password); drop !authenticate lines
    for f in /etc/sudoers /etc/sudoers.d/*; do
        [ -f "$f" ] || continue
        sed -i -E 's/NOPASSWD[[:space:]]*:[[:space:]]*//g; /!authenticate/d' "$f"
    done

    if have visudo && ! visudo -c >/dev/null 2>&1; then
        err "sudoers broke, restoring backup"
        cp -a "$snap/sudoers" /etc/sudoers
        [ -d "$snap/sudoers.d" ] && cp -a "$snap/sudoers.d/." /etc/sudoers.d/
        visudo -c >/dev/null 2>&1 || err "sudoers STILL invalid after restore - fix by hand from $CCDC_BACKUPS NOW"
        rm -rf "$snap"
        return 1
    fi
    rm -rf "$snap"
    log "sudoers cleaned of NOPASSWD/!authenticate (validated with visudo -c)"
    sudoers_grant_review
}

# tighten only - never loosen a file that is already stricter
_tighten_mode() {
    local f=$1 target=$2 cur
    cur=$(stat -c '%a' "$f" 2>/dev/null) || return 1
    if (( (8#$cur & ~8#$target) != 0 )); then
        chmod "$target" "$f" && log "chmod $target $f (was $cur)"
    fi
}

file_permissions() {
    local shadow_grp=root
    grep -q '^shadow:' /etc/group && shadow_grp=shadow
    local -A perms=(
        [/etc/shadow]=640 [/etc/gshadow]=640 [/etc/sudoers]=440
        [/etc/passwd]=644 [/etc/group]=644 [/etc/crontab]=644
        [/etc/ssh/sshd_config]=600 [/etc/cron.allow]=600 [/etc/at.allow]=600
    )
    local f
    for f in "${!perms[@]}"; do
        [ -e "$f" ] || continue
        _tighten_mode "$f" "${perms[$f]}"
        case $f in
            /etc/shadow|/etc/gshadow) chown "root:$shadow_grp" "$f" ;;
            *) chown root:root "$f" ;;
        esac
    done
    for f in /etc/sudoers.d/*; do [ -f "$f" ] && { _tighten_mode "$f" 440; chown root:root "$f"; }; done
    [ -d /root ] && _tighten_mode /root 700
    log "Sensitive file permissions reset"
}

privilege_escalation_auto() {
    lock_root
    uid0_check
    admin_group_reconcile || true
    sudoers_stuff || true
    file_permissions
    return 0
}

privilege_escalation_actions() {
    cat <<'EOF'
  auto        root lock -> UID-0 check -> admin group reconcile -> sudoers cleanup -> file perms
  root        lock root's password
  uid0        UID-0 / GID-0 anomaly check (locks extra UID-0 accounts)
  admins      admin group (sudo/wheel/admin) reconciliation from admin.txt
  sudoers     strip NOPASSWD / !authenticate (visudo-validated, auto-rollback)
  grants      list active sudoers grants (read-only)
  perms       sensitive file permissions
EOF
}

privilege_escalation_run_action() {
    case $1 in
        auto) privilege_escalation_auto ;;
        root) lock_root ;;
        uid0) uid0_check ;;
        admins) admin_group_reconcile ;;
        sudoers) sudoers_stuff ;;
        grants) sudoers_grant_review ;;
        perms) file_permissions ;;
        *) err "Unknown action: $1"; privilege_escalation_actions; return 2 ;;
    esac
}

privilege_escalation_menu() {
    ccdc_menu "04_privilege_escalation.sh - Privilege Escalation" \
        "Run all" privilege_escalation_auto \
        "Lock root password" lock_root \
        "UID-0 / GID-0 anomaly check" uid0_check \
        "Admin group reconciliation" admin_group_reconcile \
        "Sudoers cleanup (NOPASSWD / !authenticate)" sudoers_stuff \
        "Show sudoers grants" sudoers_grant_review \
        "File permissions" file_permissions
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    ccdc_main privilege_escalation "$@"
fi
