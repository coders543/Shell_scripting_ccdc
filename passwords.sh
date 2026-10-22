#!/usr/bin/env bash
# =====================================================================
#  passwords.sh - password policy, rogue-account lockout, STAGED rotation.
#  ATT&CK: Credential Access (TA0006). Runs second, right after enumeration.sh.
#  Passwords are NEVER applied by staging. Apply is a separate, explicit step:
#    sudo bash passwords.sh --run apply                       (interactive confirm)
#    sudo bash passwords.sh --run apply --confirm-pcr-submitted  (headless, human-triggered)
#  Exit code 10 from --auto = passwords staged + PCR CSV written, awaiting PCR.
# =====================================================================
[ -n "${BASH_VERSION:-}" ] || { echo "Run with bash: sudo bash $0" >&2; exit 1; }
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh" || { echo "common.sh missing next to $0" >&2; exit 1; }

declare -A pending_pw
declare -A pending_svc
PW_STAGED_THIS_RUN=0

password_policy() {
    log "Setting password policy"
    case $PKG in
        apt) pkg_install libpam-pwquality ;;
        dnf|yum|zypper) pkg_install pam ;;
        *) : ;;
    esac

    if [ -f /etc/login.defs ]; then
        backup_file /etc/login.defs
        local item
        for item in "PASS_MAX_DAYS=30" "PASS_MIN_DAYS=7" "PASS_WARN_AGE=12" "ENCRYPT_METHOD=SHA512"; do
            set_line /etc/login.defs "${item%%=*}" " " "${item#*=}"
        done
    fi

    if [ -f /etc/security/pwquality.conf ]; then
        backup_file /etc/security/pwquality.conf
        for item in "minlen=12" "lcredit=-1" "ucredit=-1" "dcredit=-1" "ocredit=-1" "retry=3"; do
            set_line /etc/security/pwquality.conf "${item%%=*}" " = " "${item#*=}"
        done
    fi

    # no empty-password logins
    local f
    for f in /etc/pam.d/common-auth /etc/pam.d/system-auth /etc/pam.d/password-auth; do
        [ -f "$f" ] || continue
        backup_file "$f"
        sed -i 's/nullok_secure//; s/nullok//' "$f"
    done

    log "Password policy set. Does NOT change any actual passwords."
}

rogue_accounts() {
    load_users || { warn "Skipping rogue-account check: no authorized user list."; return 1; }
    backup_file /etc/passwd /etc/shadow /etc/group

    local user
    for user in $(normal_users); do
        is_authorized "$user" && continue
        if [ "$user" = "${SUDO_USER:-}" ]; then
            warn "$user (you) is not in the authorized list - NOT locking the account you are using."
            continue
        fi
        if ask "$user is NOT in the authorized list. Lock (not delete) this account?" CCDC_LOCK_UNAUTHORIZED no; then
            lock_account "$user"
        fi
    done

    echo; echo "Authorized users missing from this box (README may expect them):"
    local missing=0
    for user in "${authorized[@]}"; do
        id "$user" >/dev/null 2>&1 || { echo "  - $user"; missing=1; }
    done
    [ "$missing" = 0 ] && echo "  none"

    echo; echo "Service/system accounts (UID < 1000) with a login shell:"
    local svc_accts
    svc_accts=$(awk -F: '$3 > 0 && $3 < 1000 && $7 !~ /(nologin|false|sync|shutdown|halt)$/ && $7 != "" {print $1":"$7}' /etc/passwd)
    if [ -z "$svc_accts" ]; then
        echo "  none"
    else
        echo "$svc_accts" | sed 's/^/  /'
        if ask "Set these service accounts' shells to nologin? (web/db users should not have shells)" CCDC_SERVICE_ACCOUNTS_NOLOGIN no; then
            local nologin entry
            nologin=$(command -v nologin 2>/dev/null || echo /sbin/nologin)
            [ -x "$nologin" ] || nologin=/bin/false
            for entry in $svc_accts; do
                usermod -s "$nologin" "${entry%%:*}" 2>/dev/null && log "${entry%%:*} shell ${entry#*:} -> $nologin"
            done
        fi
    fi

    echo; echo "Accounts with an EMPTY password hash:"
    local empty
    empty=$(awk -F: '$2 == "" {print $1}' /etc/shadow 2>/dev/null)
    if [ -z "$empty" ]; then
        echo "  none"
    else
        echo "$empty" | sed 's/^/  /'
        if ask "Lock all accounts with empty passwords?" CCDC_LOCK_EMPTY_PASSWORDS yes; then
            for user in $empty; do lock_account "$user"; done
        fi
    fi
}

gen_password() {
    local p
    while true; do
        p=$(LC_ALL=C tr -dc 'A-Za-z0-9@#%+=' < /dev/urandom 2>/dev/null | head -c 16)
        [[ $p =~ [a-z] && $p =~ [A-Z] && $p =~ [0-9] && $p =~ [@#%+=] ]] && { echo "$p"; return; }
    done
}

_pending_file() { echo "$CCDC_STAGING/pending_passwords.csv"; }

_csv_field() {
    local v=$1
    if [[ $v == *[,\"]* ]]; then v=${v//\"/\"\"}; v="\"$v\""; fi
    printf '%s' "$v"
}

load_pending() {
    pending_pw=(); pending_svc=()
    local f u p s
    f=$(_pending_file)
    [ -f "$f" ] || return 0
    while IFS=$'\t' read -r u p s; do
        [ -n "$u" ] || continue
        pending_pw[$u]=$p
        pending_svc[$u]=$s
    done < "$f"
}

save_pending() {
    local f u
    f=$(_pending_file)
    ( umask 077
      : > "$f"
      for u in "${!pending_pw[@]}"; do printf '%s\t%s\t%s\n' "$u" "${pending_pw[$u]}" "${pending_svc[$u]}" >> "$f"; done )
}

stage_password_changes() {
    load_pending
    echo "This STAGES new passwords. Nothing is applied to the live system yet."
    local user yn svc newpw stage_list=""
    if ccdc_noninteractive; then
        stage_list=${CCDC_STAGE_USERS:-}
        if [ -z "$stage_list" ]; then
            log "CCDC_STAGE_USERS empty - nothing staged."
            [ ${#pending_pw[@]} -gt 0 ] && warn "${#pending_pw[@]} staged-but-UNAPPLIED password(s) from an earlier run - see: passwords.sh --run show"
            return 0
        fi
    else
        echo "For each account, Enter to auto-generate a password, or type your own."
    fi
    for user in $(normal_users); do
        [ "$user" = "${SUDO_USER:-}" ] && continue
        if ccdc_noninteractive; then
            [ "$stage_list" = "all" ] || in_list "$user" $stage_list || continue
            # never silently replace a password that may already be on a submitted PCR
            if [ -n "${pending_pw[$user]:-}" ]; then log "$user already staged - keeping existing staged password"; continue; fi
            svc=${CCDC_PW_SERVICE:-local login}
            newpw=$(gen_password)
        else
            if [ -n "${pending_pw[$user]:-}" ]; then
                read -r -p "'$user' is ALREADY staged (maybe on a submitted PCR). Replace it? (yes/no) " yn || break
            else
                read -r -p "Stage a new password for '$user'? (yes/no) " yn || break
            fi
            [ "$yn" = "yes" ] || [ "$yn" = "y" ] || continue
            read -r -p "  Service/account purpose for the PCR (e.g. 'local login', 'mysql app user'): " svc
            read -r -p "  New password (blank = auto-generate): " newpw
            [ -z "$newpw" ] && newpw=$(gen_password)
        fi
        pending_pw[$user]="$newpw"
        pending_svc[$user]="${svc:-local login}"
        PW_STAGED_THIS_RUN=1
        log "Staged password change for $user (NOT yet applied)"
    done
    [ -n "${SUDO_USER:-}" ] && echo "Reminder: your own account ($SUDO_USER) was skipped - change it by hand with passwd after the PCR."
    save_pending
    write_pcr_csv
}

# writes the PCR CSV for orange team, then pauses (interactive) / signals exit 10 (auto)
write_pcr_csv() {
    [ ${#pending_pw[@]} -eq 0 ] && load_pending
    if [ ${#pending_pw[@]} -eq 0 ]; then
        echo "Nothing staged, no CSV written."
        return 0
    fi
    local ts csv user
    ts=$(date +%Y%m%d_%H%M%S)
    csv=$CCDC_PCR/pcr_password_changes_$ts.csv
    ( umask 077
      echo "User,Password,Service" > "$csv"
      for user in "${!pending_pw[@]}"; do
          echo "$(_csv_field "$user"),$(_csv_field "${pending_pw[$user]}"),$(_csv_field "${pending_svc[$user]}")" >> "$csv"
      done )
    CCDC_LAST_PCR_CSV=$csv
    log "PCR CSV written: $csv"
    echo "============================================================"
    echo " PCR CSV generated: $csv"
    echo " Review it, submit it to orange team, THEN come back and run"
    echo "   sudo bash passwords.sh --run apply"
    echo " (or 'Apply staged password changes' from the menu) to push them live."
    echo "============================================================"
    echo "Nothing has been changed on the live system."
    if ccdc_noninteractive; then
        PW_STAGED_THIS_RUN=1
    else
        echo "Script is pausing here."
        pause
    fi
}

show_staged() {
    load_pending
    if [ ${#pending_pw[@]} -eq 0 ]; then echo "No staged passwords."; return 0; fi
    echo "Staged (NOT applied) password changes:"
    local u
    for u in "${!pending_pw[@]}"; do echo "  $u  (${pending_svc[$u]})"; done
    echo "Latest PCR CSVs:"; ls -1t "$CCDC_PCR"/pcr_password_changes_*.csv 2>/dev/null | head -3 | sed 's/^/  /'
}

apply_staged_passwords() {
    load_pending
    if [ ${#pending_pw[@]} -eq 0 ]; then
        echo "No staged passwords to apply. Stage some first."
        return 0
    fi
    show_staged
    if has_extra_arg --confirm-pcr-submitted; then
        log "Apply confirmed via --confirm-pcr-submitted"
    elif ccdc_noninteractive; then
        err "Refusing to apply staged passwords non-interactively. Re-run with --run apply --confirm-pcr-submitted once the PCR is submitted."
        return 1
    elif ! ask "Apply ALL staged password changes to the live system now? Confirm you already submitted the PCR."; then
        echo "Not applying. Staged passwords are kept in $(_pending_file)."
        return 0
    fi
    backup_file /etc/shadow
    local user failed=0
    for user in "${!pending_pw[@]}"; do
        if ! id "$user" >/dev/null 2>&1; then
            warn "$user no longer exists - skipped"; failed=1; continue
        fi
        if echo "${user}:${pending_pw[$user]}" | chpasswd; then
            have chage && chage -m 7 -M 30 -W 12 "$user" 2>/dev/null
            log "APPLIED staged password for $user"
            unset "pending_pw[$user]" "pending_svc[$user]"
        else
            err "chpasswd failed for $user - still staged"; failed=1
        fi
    done
    local f ts
    f=$(_pending_file); ts=$(date +%Y%m%d_%H%M%S)
    [ -f "$f" ] && cp -a "$f" "$CCDC_STAGING/applied_$ts.tsv"
    save_pending
    if [ ${#pending_pw[@]} -eq 0 ]; then rm -f "$f"; echo "Applied. Staged list cleared."; fi
    return $failed
}

passwords_auto() {
    password_policy
    rogue_accounts || true
    stage_password_changes
    if [ "$PW_STAGED_THIS_RUN" = 1 ]; then
        echo
        echo "############################################################"
        echo "#  PASSWORDS STAGED - NOT APPLIED.                         #"
        echo "#  Submit ${CCDC_LAST_PCR_CSV:-the PCR CSV in $CCDC_PCR}"
        echo "#  then run: sudo bash passwords.sh --run apply            #"
        echo "############################################################"
        return 10
    fi
    return 0
}

passwords_actions() {
    cat <<'EOF'
  auto     policy -> rogue accounts -> stage (CCDC_STAGE_USERS) -> PCR CSV; exits 10 if staged
  policy   password complexity/aging policy
  rogue    lock-not-delete unauthorized accounts, service-account shells, empty passwords
  stage    stage new passwords + write PCR CSV (does not apply)
  csv      re-write the PCR CSV from what is currently staged
  show     list staged (unapplied) changes
  apply    apply staged passwords (interactive confirm, or --confirm-pcr-submitted)
EOF
}

passwords_run_action() {
    case $1 in
        auto) passwords_auto ;;
        policy) password_policy ;;
        rogue) rogue_accounts ;;
        stage) stage_password_changes ;;
        csv) write_pcr_csv ;;
        show) show_staged ;;
        apply) apply_staged_passwords ;;
        *) err "Unknown action: $1"; passwords_actions; return 2 ;;
    esac
}

passwords_menu() {
    ccdc_menu "passwords.sh - Credential Access & Rogue Accounts" \
        "Password policy (complexity/aging, no empty passwords)" password_policy \
        "Rogue/unauthorized accounts (lock, never delete)" rogue_accounts \
        "STAGE password changes + write PCR CSV (does not apply)" stage_password_changes \
        "Show staged (unapplied) changes" show_staged \
        "Apply staged password changes (after PCR submitted)" apply_staged_passwords
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    ccdc_main passwords "$@"
fi
