#!/usr/bin/env bash
# =====================================================================
#  01_initial_access.sh - backups, patching, README-driven service
#  disable + hardening (SSH, Apache/httpd, Samba, FTP, DNS).
#  ATT&CK: Initial Access (TA0001) - exposed services / default config.
#  Usage: sudo bash 01_initial_access.sh [--auto] [--config FILE] [--run ACTION]
# =====================================================================
[ -n "${BASH_VERSION:-}" ] || { echo "Run with bash: sudo bash $0" >&2; exit 1; }
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh" || { echo "common.sh missing next to $0" >&2; exit 1; }

backup_files() {
    local files_to_backup=(
        /etc/passwd /etc/group /etc/shadow /etc/gshadow /etc/sudoers
        /etc/hosts /etc/hosts.allow /etc/hosts.deny /etc/login.defs
        /etc/sysctl.conf /etc/environment /etc/ssh/sshd_config
        /etc/crontab /etc/fstab
    )
    backup_file "${files_to_backup[@]}"
    [ -d /etc/sudoers.d ] && tar -czf "$CCDC_BACKUPS/etc_sudoers.d_$(date +%Y%m%d_%H%M%S).tar.gz" -C / etc/sudoers.d 2>/dev/null
    log "Config backups saved to $CCDC_BACKUPS (pristine copies in $CCDC_BACKUPS/pristine)"

    backup_runtime_dirs
}

# size-aware snapshot of where malware lives/hides, before anything is cleaned
backup_runtime_dirs() {
    local rt_ts rt_dir d safe_name log_size_kb wd
    rt_ts=$(date +%Y%m%d_%H%M%S)
    rt_dir=$CCDC_BACKUPS/runtime_$rt_ts
    mkdir -p "$rt_dir"

    if [ -d /tmp ]; then
        tar -czf "$rt_dir/tmp.tar.gz" -C / tmp 2>/dev/null
        log "Backed up /tmp -> $rt_dir/tmp.tar.gz"
    fi
    [ -d /dev/shm ] && tar -czf "$rt_dir/dev_shm.tar.gz" -C / dev/shm 2>/dev/null
    [ -d /var/tmp ] && tar -czf "$rt_dir/var_tmp.tar.gz" -C / var/tmp 2>/dev/null

    for d in /var/spool/cron /var/spool/cron/crontabs /var/spool/at /var/spool/mail /etc/crontabs; do
        if [ -d "$d" ]; then
            safe_name=$(echo "$d" | tr '/' '_')
            tar -czf "$rt_dir/${safe_name}.tar.gz" -C / "${d#/}" 2>/dev/null
        fi
    done
    log "Backed up cron/mail spool directories -> $rt_dir"

    if [ -d /var/log ]; then
        log_size_kb=$(du -sk /var/log 2>/dev/null | awk '{print $1}')
        if [ -n "$log_size_kb" ] && [ "$log_size_kb" -lt 512000 ]; then
            tar -czf "$rt_dir/var_log.tar.gz" -C / var/log 2>/dev/null
            log "Backed up /var/log (${log_size_kb}KB) -> $rt_dir/var_log.tar.gz"
        elif ask "/var/log is ${log_size_kb:-unknown}KB (large). Back it up anyway?" CCDC_BACKUP_LARGE_VARLOG no; then
            tar -czf "$rt_dir/var_log.tar.gz" -C / var/log 2>/dev/null
            log "Backed up /var/log (large, confirmed) -> $rt_dir/var_log.tar.gz"
        else
            log "/var/log backup skipped (too large, not confirmed)"
        fi
    fi

    for wd in /var/www /srv/www /usr/share/nginx; do
        if [ -d "$wd" ]; then
            safe_name=$(echo "$wd" | tr '/' '_')
            tar -czf "$rt_dir/${safe_name}.tar.gz" -C / "${wd#/}" 2>/dev/null
            log "Backed up $wd -> $rt_dir/${safe_name}.tar.gz"
        fi
    done

    log "Runtime directory backups complete: $rt_dir"
}

updates() {
    if ! ask "Run a full package update/upgrade now? (can take a while; no reboot is done)" CCDC_RUN_UPDATES yes; then
        log "Package updates skipped"
        return 0
    fi
    log "Running package updates (no reboot)"
    pkg_update_all
    # do NOT reboot here - scored services may not come back
    log "Current kernel: $(uname -r) -- do not reboot without a plan, scored services may not come back"
}

# ---------------------------------------------------------------
# config snapshot / rollback for service hardening
# ---------------------------------------------------------------
cfg_snapshot() {
    local snap f
    snap=$(mktemp -d "$CCDC_STATE/snap.XXXXXX") || return 1
    for f in "$@"; do
        [ -e "$f" ] && tar -cf "$snap/$(echo "$f" | tr '/' '_').tar" -C / "${f#/}" 2>/dev/null
    done
    echo "$snap"
}

cfg_rollback() {
    local snap=$1 t
    for t in "$snap"/*.tar; do [ -f "$t" ] && tar -xf "$t" -C /; done
    warn "Rolled back config from $snap"
}

# restart, and if the service won't come up, restore the snapshot and restart again
restart_or_rollback() {
    local snap=$1; shift
    if restart_service "$@"; then
        local n i
        for n in "$@"; do
            svc_exists "$n" || continue
            for i in 1 2 3 4 5; do svc_is_active "$n" && { rm -rf "$snap"; return 0; }; sleep 1; done
            break
        done
    fi
    err "$1 did not come back after hardening - restoring previous config"
    cfg_rollback "$snap"
    restart_service "$@"
    return 1
}

# ---------------------------------------------------------------
# SSH
# ---------------------------------------------------------------
ssh_hardening() {
    [ -f "$SSHD_CONF" ] || { echo "No $SSHD_CONF - skipping SSH hardening."; return 0; }
    local root_login=no
    if [ -z "${SUDO_USER:-}" ] && [ -n "${SSH_CONNECTION:-}" ]; then
        warn "You appear to be logged in over SSH directly as root. PermitRootLogin no blocks NEW root logins."
        ask "Disable SSH root login anyway?" CCDC_SSH_DISABLE_ROOT_LOGIN yes || root_login=""
    fi
    sshd_begin_change || return 1
    local item
    for item in ${root_login:+"PermitRootLogin=no"} "PermitEmptyPasswords=no" "StrictModes=yes" \
                "LoginGraceTime=20" "MaxAuthTries=3" "X11Forwarding=no" \
                "HostbasedAuthentication=no" "LogLevel=VERBOSE"; do
        sshd_set "${item%%=*}" "${item#*=}"
    done
    if sshd_commit_change; then
        log "SSH hardened and restarted"
    else
        err "SSH hardening rolled back - sshd config unchanged"
        return 1
    fi
}

# ---------------------------------------------------------------
# APACHE / HTTPD
# ---------------------------------------------------------------
_apache_no_indexes() {
    local f=$1 tmp
    tmp=$(mktemp "$CCDC_STATE/apache.XXXXXX") || return 1
    awk '{
        if ($1 == "Options") {
            match($0, /^[ \t]*/); ind = substr($0, 1, RLENGTH)
            out = $1; n = 0; changed = 0
            for (i = 2; i <= NF; i++) {
                if ($i == "Indexes") { changed = 1; continue }
                if ($i == "+Indexes") { $i = "-Indexes"; changed = 1 }
                out = out " " $i; n++
            }
            if (changed) {
                if (n == 0) out = out " None"
                print ind out; next
            }
        }
        print
    }' "$f" > "$tmp" && cat "$tmp" > "$f"
    rm -f "$tmp"
}

harden_apache() {
    local conf="" confdir="" sec
    if [ -f /etc/apache2/apache2.conf ]; then conf=/etc/apache2/apache2.conf; confdir=/etc/apache2
    elif [ -f /etc/httpd/conf/httpd.conf ]; then conf=/etc/httpd/conf/httpd.conf; confdir=/etc/httpd
    fi
    if [ -z "$conf" ]; then
        echo "Apache/httpd not found (README web=${need[web]:-no}) - nothing to harden. (nginx is not handled here.)"
        return 0
    fi
    local snap
    snap=$(cfg_snapshot "$confdir")
    backup_file "$conf"

    if [ -d /etc/apache2/conf-enabled ]; then
        sec=/etc/apache2/conf-enabled/security.conf
        [ -L "$sec" ] && sec=$(readlink -f "$sec")
    else
        sec=$conf
    fi
    set_line "$sec" ServerTokens " " Prod
    set_line "$sec" ServerSignature " " Off
    set_line "$sec" TraceEnable " " Off

    # strip Indexes without mixing +/- and bare options (Apache 2.4 rejects that)
    local f
    grep -rlE "^[[:space:]]*Options[[:space:]].*Indexes" "$confdir" 2>/dev/null | while read -r f; do
        _apache_no_indexes "$f"
    done

    # dedicated unprivileged run user, never root
    if id www-data >/dev/null 2>&1 && [ -f /etc/apache2/envvars ]; then
        set_line /etc/apache2/envvars "export APACHE_RUN_USER" "=" "www-data"
        set_line /etc/apache2/envvars "export APACHE_RUN_GROUP" "=" "www-data"
    fi
    chown -R root:root "$confdir" 2>/dev/null

    if have a2dismod; then
        local mod
        for mod in autoindex status info userdir; do a2dismod "$mod" >/dev/null 2>&1; done
    fi

    local ctl=""
    for ctl in apache2ctl apachectl httpd; do have "$ctl" && break; ctl=""; done
    if [ -n "$ctl" ] && ! "$ctl" -t >/dev/null 2>&1; then
        err "Apache configtest failed after hardening: $("$ctl" -t 2>&1 | tail -3)"
        cfg_rollback "$snap"
        return 1
    fi
    restart_or_rollback "$snap" apache2 httpd && log "Apache/httpd hardened (version hiding, no indexing, no TRACE)"
}

# ---------------------------------------------------------------
# SAMBA
# ---------------------------------------------------------------
harden_samba() {
    local conf=/etc/samba/smb.conf
    [ -f "$conf" ] || { echo "Samba not installed/not found."; return 0; }
    local snap
    snap=$(cfg_snapshot "$conf")
    backup_file "$conf"

    grep -q "restrict anonymous" "$conf" || sed -i '/^\[global\]/a\   restrict anonymous = 2' "$conf"
    grep -q "^\s*server min protocol" "$conf" || sed -i '/^\[global\]/a\   server min protocol = SMB2' "$conf"
    grep -q "^\s*smb encrypt" "$conf" || sed -i '/^\[global\]/a\   smb encrypt = required' "$conf"
    grep -q "^\s*map to guest" "$conf" || sed -i '/^\[global\]/a\   map to guest = never' "$conf"

    if ask "Disable guest access on all shares (set 'guest ok = no')?" CCDC_SAMBA_DISABLE_GUEST no; then
        sed -i 's/^\(\s*guest ok\s*=\s*\)yes/\1no/I' "$conf"
    fi

    if have testparm && ! testparm -s "$conf" >/dev/null 2>&1; then
        err "testparm rejected smb.conf after hardening"
        cfg_rollback "$snap"
        return 1
    fi
    restart_or_rollback "$snap" smbd smb && { restart_service nmbd nmb >/dev/null 2>&1; log "Samba hardened (no anonymous, SMB2+ min, encryption required)"; }
}

# ---------------------------------------------------------------
# FTP (vsftpd / proftpd)
# ---------------------------------------------------------------
harden_ftp() {
    local vconf=""
    [ -f /etc/vsftpd.conf ] && vconf=/etc/vsftpd.conf
    [ -z "$vconf" ] && [ -f /etc/vsftpd/vsftpd.conf ] && vconf=/etc/vsftpd/vsftpd.conf
    if [ -n "$vconf" ]; then
        local snap item cert
        snap=$(cfg_snapshot "$vconf")
        backup_file "$vconf"
        local settings=("anonymous_enable=NO" "anon_upload_enable=NO" "anon_mkdir_write_enable=NO"
                        "chroot_local_user=YES" "allow_writeable_chroot=YES" "local_enable=YES"
                        "write_enable=$(is_yes "${CCDC_FTP_WRITE_ENABLE:-no}" && echo YES || echo NO)"
                        "ftpd_banner=Authorized_use_only")
        # ssl_enable=YES without a cert stops vsftpd from starting
        cert=$(awk -F= '/^[[:space:]]*rsa_cert_file/ {print $2}' "$vconf" | tr -d '[:space:]')
        if [ -n "$cert" ] && [ -f "$cert" ]; then
            settings+=("ssl_enable=YES" "allow_anon_ssl=NO")
        else
            warn "vsftpd has no usable rsa_cert_file - leaving ssl_enable alone so FTP keeps working"
        fi
        for item in "${settings[@]}"; do
            set_line "$vconf" "${item%%=*}" "=" "${item#*=}"
        done
        restart_or_rollback "$snap" vsftpd && log "vsftpd hardened (no anonymous, chroot, no anon write)"
    elif [ -f /etc/proftpd/proftpd.conf ] || [ -f /etc/proftpd.conf ]; then
        local pconf=/etc/proftpd/proftpd.conf snap
        [ -f "$pconf" ] || pconf=/etc/proftpd.conf
        snap=$(cfg_snapshot "$pconf")
        backup_file "$pconf"
        grep -q "DefaultRoot" "$pconf" || echo "DefaultRoot ~" >> "$pconf"
        # comment out the whole <Anonymous> block, not just its opening tag
        sed -i '/^[[:space:]]*<Anonymous/,/^[[:space:]]*<\/Anonymous>/ s/^/#DISABLED /' "$pconf"
        if have proftpd && ! proftpd -t -c "$pconf" >/dev/null 2>&1; then
            err "proftpd -t rejected config after hardening"
            cfg_rollback "$snap"; return 1
        fi
        restart_or_rollback "$snap" proftpd && log "proftpd hardened (chroot default root, anonymous disabled)"
    else
        echo "No FTP daemon (vsftpd/proftpd) found."
    fi
}

# ---------------------------------------------------------------
# DNS (BIND / named)
# ---------------------------------------------------------------
harden_dns() {
    local conf="" c
    for c in /etc/bind/named.conf.options /etc/named.conf /etc/bind/named.conf; do
        [ -f "$c" ] && { conf=$c; break; }
    done
    if [ -z "$conf" ]; then
        echo "No BIND/named config found."
        return 0
    fi
    local snap
    snap=$(cfg_snapshot "$conf")
    backup_file "$conf"

    # no open resolver; hide version
    if ! grep -q "allow-recursion" "$conf"; then
        sed -i '/options {/a\        allow-recursion { localhost; localnets; };\n        version "not disclosed";' "$conf"
        log "Added allow-recursion + version hiding to $conf"
    fi

    if have named-checkconf; then
        local main=/etc/named.conf
        [ -f /etc/bind/named.conf ] && main=/etc/bind/named.conf
        if ! named-checkconf "$main" >> "$LOG" 2>&1; then
            err "named-checkconf failed after hardening - restoring $conf, NOT restarting"
            cfg_rollback "$snap"
            return 1
        fi
    fi
    restart_or_rollback "$snap" bind9 named && log "DNS (BIND/named) hardened - recursion restricted, version hidden"
}

# ---------------------------------------------------------------
# README-DRIVEN: stop what isn't needed, harden what is
# ---------------------------------------------------------------
CCDC_ALWAYS_SUSPECT_UNITS="telnet.socket telnetd inetd xinetd rsh.socket rlogin.socket rexec.socket tftp tftpd-hpa tftp.socket avahi-daemon cups snmpd rpcbind nfs-server nfs-kernel-server"

disable_unneeded_services() {
    readme_services || { warn "Skipping service disable: no README answers."; return 1; }
    local svc unit found=0
    echo "Services running that the README says this box does NOT need:"
    for svc in "${!CCDC_SVC_UNITS[@]}"; do
        [ "$svc" = ssh ] && continue
        [ "${need[$svc]:-no}" = "yes" ] && continue
        for unit in ${CCDC_SVC_UNITS[$svc]}; do
            svc_exists "$unit" && svc_is_active "$unit" || continue
            found=1
            if ask "  $unit is running but README says no '$svc'. Stop + disable it (not uninstall)?" CCDC_DISABLE_UNNEEDED no; then
                svc_stop_disable "$unit" && log "Stopped + disabled $unit (README: no $svc). Undo: re-enable/start $unit"
            fi
        done
    done
    for unit in $CCDC_ALWAYS_SUSPECT_UNITS; do
        [ "$unit" = rpcbind ] && [ "${need[samba]:-no}" = yes ] && continue
        svc_exists "${unit%.socket}" || svc_exists "$unit" || continue
        svc_is_active "$unit" || continue
        found=1
        if ask "  $unit is running (legacy/unneeded on most scored boxes). Stop + disable it?" CCDC_DISABLE_UNNEEDED no; then
            svc_stop_disable "$unit" && log "Stopped + disabled $unit"
        fi
    done
    [ "$found" = 0 ] && echo "  none found"
    if [ "${need[ssh]:-no}" = "no" ] && { svc_is_active ssh || svc_is_active sshd; }; then
        echo "NOTE: sshd is running but README says no ssh. Not auto-disabled (you may be using it) - stop it by hand if appropriate."
    fi
}

service_hardening() {
    readme_services || { warn "Skipping service hardening: no README answers."; return 1; }
    [ "${need[ssh]:-no}" = "yes" ] && ssh_hardening
    [ "${need[web]:-no}" = "yes" ] && harden_apache
    [ "${need[samba]:-no}" = "yes" ] && harden_samba
    [ "${need[ftp]:-no}" = "yes" ] && harden_ftp
    [ "${need[dns]:-no}" = "yes" ] && harden_dns
    return 0
}

initial_access_auto() {
    backup_files
    readme_services || warn "No README answers - service steps will be skipped."
    updates
    disable_unneeded_services || true
    service_hardening || true
    return 0
}

initial_access_actions() {
    cat <<'EOF'
  auto       backups -> updates -> disable unneeded -> service hardening
  backup     config + runtime-dir backups (/tmp, cron/mail spools, /var/log, web roots)
  updates    full package update (no reboot)
  disable    stop+disable services the README says are not needed
  harden     README-driven SSH/Apache/Samba/FTP/DNS hardening
  ssh|apache|samba|ftp|dns   harden one service
EOF
}

initial_access_run_action() {
    case $1 in
        auto) initial_access_auto ;;
        backup) backup_files ;;
        updates) updates ;;
        disable) disable_unneeded_services ;;
        harden) service_hardening ;;
        ssh) ssh_hardening ;;
        apache) harden_apache ;;
        samba) harden_samba ;;
        ftp) harden_ftp ;;
        dns) harden_dns ;;
        *) err "Unknown action: $1"; initial_access_actions; return 2 ;;
    esac
}

initial_access_menu() {
    ccdc_menu "01_initial_access.sh - Initial Access (exposed services)" \
        "Run all (backups -> updates -> disable unneeded -> harden)" initial_access_auto \
        "Backups (configs + /tmp + /var runtime dirs)" backup_files \
        "Updates (no reboot)" updates \
        "Stop/disable services the README doesn't need" disable_unneeded_services \
        "Service/SSH hardening (README-driven)" service_hardening \
        "SSH hardening only" ssh_hardening \
        "Apache/httpd hardening only" harden_apache \
        "Samba hardening only" harden_samba \
        "FTP hardening only" harden_ftp \
        "DNS (BIND) hardening only" harden_dns
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    ccdc_main initial_access "$@"
fi
