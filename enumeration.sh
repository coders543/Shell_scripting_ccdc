#!/usr/bin/env bash
# =====================================================================
#  enumeration.sh - asset inventory + enumeration. RUN THIS FIRST.
#  ATT&CK: setup step; counters adversary Reconnaissance (TA0043).
#  Read-only except for writing reports under ~root/ccdc/inventory.
#  Usage: sudo bash enumeration.sh [--auto] [--config FILE] [--run ACTION]
# =====================================================================
[ -n "${BASH_VERSION:-}" ] || { echo "Run with bash: sudo bash $0" >&2; exit 1; }
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh" || { echo "common.sh missing next to $0" >&2; exit 1; }

asset_inventory() {
    log "Running asset inventory"
    local OUT=$CCDC_INVENTORY

    {
        echo "=== Hostname / OS ==="
        hostname; cat /etc/os-release 2>/dev/null
        echo; echo "=== Kernel ==="; uname -a
        echo; echo "=== Virtualization ==="
        if have systemd-detect-virt; then systemd-detect-virt 2>/dev/null; else grep -m1 -i hypervisor /proc/cpuinfo 2>/dev/null || echo "unknown"; fi
        echo; echo "=== Interfaces / addresses ==="
        if have ip; then ip -brief addr 2>/dev/null || ip addr; else ifconfig -a 2>/dev/null; fi
        echo; echo "=== Routes ==="
        if have ip; then ip route 2>/dev/null; else route -n 2>/dev/null; fi
        echo; echo "=== DNS resolvers ==="; cat /etc/resolv.conf 2>/dev/null
        echo; echo "=== Package manager / init ==="; echo "pkg=${PKG:-none} init=$INIT_SYS"
    } > "$OUT/system.txt"

    list_listening > "$OUT/listening_ports.txt" 2>&1

    ps auxww > "$OUT/processes.txt" 2>/dev/null || ps > "$OUT/processes.txt"

    case $PKG in
        apt)    dpkg -l > "$OUT/packages.txt" ;;
        dnf|yum|zypper) rpm -qa > "$OUT/packages.txt" ;;
        pacman) pacman -Qe > "$OUT/packages.txt" ;;
        apk)    apk info > "$OUT/packages.txt" ;;
    esac

    case $INIT_SYS in
        systemd)
            systemctl list-units --type=service --state=running > "$OUT/running_services.txt"
            systemctl list-unit-files --type=service --state=enabled > "$OUT/enabled_services.txt" ;;
        openrc)
            rc-status -a > "$OUT/running_services.txt" 2>&1 ;;
        *)
            service --status-all > "$OUT/running_services.txt" 2>&1 ;;
    esac

    {
        echo "=== /etc/passwd (login shells) ==="
        awk -F: '$7 !~ /(nologin|false)$/ {print $1" uid="$3" gid="$4" home="$6" shell="$7}' /etc/passwd
        echo; echo "=== UID 0 accounts ==="; awk -F: '$3 == 0 {print $1}' /etc/passwd
        echo; echo "=== Admin-ish groups ==="; grep -E '^(sudo|wheel|admin|root):' /etc/group
        echo; echo "=== sudoers (active lines) ==="
        grep -hEv '^[[:space:]]*(#|$)' /etc/sudoers /etc/sudoers.d/* 2>/dev/null
        echo; echo "=== authorized_keys files ==="
        awk -F: '{print $6}' /etc/passwd | sort -u | while read -r h; do
            for k in "$h/.ssh/authorized_keys" "$h/.ssh/authorized_keys2"; do
                [ -f "$k" ] && echo "$k ($(grep -cEv '^[[:space:]]*(#|$)' "$k" 2>/dev/null) keys)"
            done
        done
        echo; echo "=== Crontabs present ==="
        ls -la /var/spool/cron /var/spool/cron/crontabs /etc/cron.d 2>/dev/null
    } > "$OUT/accounts.txt"

    if have nmap; then
        nmap -sT -p- -oN "$OUT/self_nmap.txt" 127.0.0.1 >/dev/null 2>&1 &
        log "Self nmap scan kicked off in background -> $OUT/self_nmap.txt"
    fi

    lsblk > "$OUT/block_devices.txt" 2>/dev/null
    mount > "$OUT/mounts.txt"

    find / -xdev -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null > "$OUT/suid_sgid.txt"
    find / -xdev -perm -2 ! -type l 2>/dev/null > "$OUT/world_writable.txt"

    log "Inventory complete, files in $OUT. READ THESE before changing anything."
}

# scored service -> what it depends on (DB behind web, LDAP behind SSH, ...)
map_critical_dependencies() {
    local out=$CCDC_INVENTORY/dependencies.txt
    log "Mapping critical-service dependencies -> $out"
    {
        echo "=== Established connections by process (who talks to whom) ==="
        if have ss; then
            ss -tnp state established 2>/dev/null | awk 'NR>1 {print $NF"  "$3" -> "$4}' | sort | uniq -c | sort -rn
        else
            netstat -tnp 2>/dev/null | awk '$6=="ESTABLISHED" {print $7"  "$4" -> "$5}' | sort | uniq -c | sort -rn
        fi
        echo
        echo "=== Authentication sources (AD/LDAP behind SSH/sudo?) ==="
        grep -E '^(passwd|group|shadow):' /etc/nsswitch.conf 2>/dev/null
        for f in /etc/sssd/sssd.conf /etc/krb5.conf /etc/ldap.conf /etc/openldap/ldap.conf /etc/ldap/ldap.conf /etc/samba/smb.conf; do
            [ -f "$f" ] && echo "present: $f"
        done
        have realm && realm list 2>/dev/null
        echo
        echo "=== Database/backend references in web/app roots (credentials masked) ==="
        for d in /var/www /srv /opt /usr/share/nginx; do
            [ -d "$d" ] || continue
            grep -rIEn --include='*.php' --include='*.env' --include='.env' --include='*.ini' --include='*.conf' \
                 --include='*.yml' --include='*.yaml' --include='*.json' --include='*.py' --include='*.js' \
                 -e 'DB_HOST' -e 'DATABASE_URL' -e 'mysqli?_connect' -e 'jdbc:' -e 'mongodb(\+srv)?://' -e 'postgres(ql)?://' -e 'redis://' \
                 "$d" 2>/dev/null | head -n 200 | sed -E 's#://[^:/@[:space:]]+:[^@[:space:]]+@#://***:***@#g'
        done
        echo
        echo "=== Listening services and owning process ==="
        list_listening
    } > "$out" 2>&1
    echo "Dependency map: $out  (scored service + its dependencies = critical services)"
}

hunt_local_ports() {
    echo "Listening TCP/UDP ports and owning process right now:"
    list_listening
    echo
    echo "---------------- Cross-referencing against known watchlists ----------------"
    local port name risk rest found_any=no
    for port in $(listening_ports); do
        if [ -n "${PORT_WATCHLIST[$port]:-}" ]; then
            name="${PORT_WATCHLIST[$port]%%|*}"
            risk="${PORT_WATCHLIST[$port]#*|}"
            printf "  [HIGH-VALUE] %5s  %-14s %s\n" "$port" "$name" "$risk"
            found_any=yes
        fi
        if [ -n "${MALWARE_PORT_WATCHLIST[$port]:-}" ]; then
            name="${MALWARE_PORT_WATCHLIST[$port]%%|*}"
            rest="${MALWARE_PORT_WATCHLIST[$port]#*|}"
            printf "  [MALWARE/C2] %5s  %-24s %s\n" "$port" "$name" "${rest#*|}"
            found_any=yes
        fi
    done
    [ "$found_any" = "no" ] && echo "  Nothing listening matches either watchlist. Good."

    echo
    echo "Tip: for an unrecognized PID, run 'ps -p <PID> -o pid,user,cmd' and check"
    echo "if the binary lives somewhere weird like /tmp, /dev/shm, or /var/tmp."
    log "Local port hunt complete"
}

ensure_nmap() {
    if ! have nmap; then
        echo "nmap not installed, installing..."
        pkg_install nmap
    fi
    have nmap || { warn "Could not install nmap. Skipping enumeration."; return 1; }
}

# nmap_scan_report "targets" - the scan + formatted report (no prompts)
nmap_scan_report() {
    local targets=$1 ts outdir report port name risk rest cat note found_any tcp_open
    ts=$(date +%Y%m%d_%H%M%S)
    outdir=$CCDC_INVENTORY/nmap_$ts
    mkdir -p "$outdir"
    report=$outdir/enumeration_report.txt

    log "Starting comprehensive nmap enumeration of: $targets"
    echo "This can take a while with -p- -sS -sU -T4. Running..."

    # word-splitting of $targets is intentional (multiple hosts/CIDRs)
    # shellcheck disable=SC2086
    nmap -p- -sS -sV -O -sC --script vuln -T4 -oA "$outdir/scan" $targets > "$outdir/raw_stdout.txt" 2>&1
    # shellcheck disable=SC2086
    nmap -sU --top-ports 100 -T4 -oN "$outdir/udp_top100.txt" $targets >/dev/null 2>&1

    {
        echo "============================================================"
        echo " CCDC ENUMERATION REPORT"
        echo " Generated: $(date)"
        echo " Targets:   $targets"
        echo "============================================================"
        echo
        echo "---------------- WATCHLIST PORTS FOUND OPEN (check these first) ----------------"
        found_any=no
        for port in "${!PORT_WATCHLIST[@]}"; do
            if grep -qE "^${port}/(tcp|udp).*open" "$outdir/scan.nmap" "$outdir/udp_top100.txt" 2>/dev/null; then
                name="${PORT_WATCHLIST[$port]%%|*}"
                risk="${PORT_WATCHLIST[$port]#*|}"
                printf "  [%5s] %-14s %s\n" "$port" "$name" "$risk"
                found_any=yes
            fi
        done
        [ "$found_any" = "no" ] && echo "  None of the watchlist ports were found open. Good."
        echo
        echo "---------------- KNOWN MALWARE/C2/RMM PORT MATCHES (hunting, not a block list) ----------------"
        found_any=no
        for port in "${!MALWARE_PORT_WATCHLIST[@]}"; do
            if grep -qE "^${port}/(tcp|udp).*open" "$outdir/scan.nmap" "$outdir/udp_top100.txt" 2>/dev/null; then
                name="${MALWARE_PORT_WATCHLIST[$port]%%|*}"
                rest="${MALWARE_PORT_WATCHLIST[$port]#*|}"
                cat="${rest%%|*}"
                note="${rest#*|}"
                printf "  [%6s] %-24s (%s)\n      %s\n" "$port" "$name" "$cat" "$note"
                found_any=yes
            fi
        done
        [ "$found_any" = "no" ] && echo "  No known malware/C2/RMM default ports found listening. Good."
        echo
        echo "---------------- OPEN TCP PORTS / SERVICES (full) ----------------"
        awk '
            /^Nmap scan report for/ { host=$0; print ""; print host }
            /^[0-9]+\/tcp/ { print "  " $0 }
        ' "$outdir/scan.nmap"
        echo
        echo "---------------- OS GUESS ----------------"
        grep -A2 "OS details\|Running:" "$outdir/scan.nmap" 2>/dev/null
        echo
        echo "---------------- VULN SCRIPT FINDINGS (review these first) ----------------"
        awk '/VULNERABLE|CVE-/' "$outdir/scan.nmap" 2>/dev/null
        echo
        echo "---------------- UDP TOP 100 ----------------"
        grep "^[0-9]" "$outdir/udp_top100.txt" 2>/dev/null
        echo
        echo "---------------- SUMMARY COUNTS ----------------"
        tcp_open=$(grep -c "^[0-9]*/tcp.*open" "$outdir/scan.nmap" 2>/dev/null)
        echo "Open TCP ports found: ${tcp_open:-0}"
        echo
        echo "Full raw output: $outdir/scan.nmap"
        echo "XML (machine-readable): $outdir/scan.xml"
        echo "============================================================"
    } > "$report"

    echo "============================================================"
    echo " Enumeration report ready: $report"
    echo "============================================================"
    log "Nmap enumeration complete -> $report"
}

enumerate_nmap() {
    ensure_nmap || return 1
    local targets
    targets=$(prompt_value "Target(s) to scan (space separated IPs/CIDRs/hostnames, blank = localhost):" CCDC_NMAP_TARGETS "127.0.0.1")
    if ask "Run the scan in the background (keep working while it runs)?" CCDC_NMAP_BACKGROUND no; then
        ( nmap_scan_report "$targets" >/dev/null 2>&1 ) &
        log "nmap enumeration running in background (pid $!) -> $CCDC_INVENTORY/nmap_*/enumeration_report.txt"
    else
        nmap_scan_report "$targets"
    fi
}

enumeration_auto() {
    if ask "Run the full nmap enumeration first? (recommended - can take a while on -p- -A)" CCDC_RUN_NMAP no; then
        enumerate_nmap
    fi
    asset_inventory
    map_critical_dependencies
    hunt_local_ports
    echo
    echo "Enumeration done. Review $CCDC_INVENTORY before running anything that changes the box."
    return 0
}

enumeration_actions() {
    cat <<'EOF'
  auto           nmap (optional) -> inventory -> dependency map -> local port hunt
  inventory      asset inventory only
  dependencies   critical-service dependency map
  ports          fast local port hunt (ss + watchlists)
  nmap           full nmap enumeration + formatted report
EOF
}

enumeration_run_action() {
    case $1 in
        auto) enumeration_auto ;;
        inventory) asset_inventory ;;
        dependencies) map_critical_dependencies ;;
        ports) hunt_local_ports ;;
        nmap) enumerate_nmap ;;
        *) err "Unknown action: $1"; enumeration_actions; return 2 ;;
    esac
}

enumeration_menu() {
    ccdc_menu "enumeration.sh - Asset Inventory & Enumeration (run first)" \
        "Run all enumeration (nmap optional -> inventory -> deps -> port hunt)" enumeration_auto \
        "Asset inventory" asset_inventory \
        "Critical-service dependency map (Finding the Monkey)" map_critical_dependencies \
        "Fast local port hunt (no scan needed, ss + watchlists)" hunt_local_ports \
        "Full nmap enumeration (formatted report, watchlist ports)" enumerate_nmap
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    ccdc_main enumeration "$@"
fi
