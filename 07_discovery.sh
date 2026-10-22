#!/usr/bin/env bash
# =====================================================================
#  07_discovery.sh - hunt your own box the way red team would:
#  nmap + local port hunt (sourced from enumeration.sh), plus an IOC
#  hunt (odd PIDs, temp-dir binaries, service accounts running shells,
#  recon commands, unexpected listeners) and a contain/eradicate loop.
#  ATT&CK: Discovery (TA0007). Re-run this every hour or so.
# =====================================================================
[ -n "${BASH_VERSION:-}" ] || { echo "Run with bash: sudo bash $0" >&2; exit 1; }
_ccdc_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
. "$_ccdc_dir/common.sh" || { echo "common.sh missing next to $0" >&2; exit 1; }
. "$_ccdc_dir/enumeration.sh" || { echo "enumeration.sh missing next to $0" >&2; exit 1; }

IOC_SUSPECT_PIDS=()

_expected_ports() {
    local p="22 111 ${CCDC_EXPECTED_PORTS:-}"
    if readme_load_saved; then
        [ "${need[web]:-no}" = yes ] && p+=" 80 443"
        [ "${need[ftp]:-no}" = yes ] && p+=" 20 21"
        [ "${need[dns]:-no}" = yes ] && p+=" 53"
        [ "${need[mail]:-no}" = yes ] && p+=" 25 110 143 465 587 993 995"
        [ "${need[samba]:-no}" = yes ] && p+=" 137 138 139 445"
        [ "${need[mysql]:-no}" = yes ] && p+=" 3306"
        [ "${need[postgres]:-no}" = yes ] && p+=" 5432"
    fi
    echo "$p ${CCDC_EXTRA_TCP_IN:-} ${CCDC_EXTRA_UDP_IN:-}" | tr ',' ' '
}

ioc_hunt() {
    local ts report pid exe cwd uid user comm args flags
    ts=$(date +%Y%m%d_%H%M%S)
    report=$CCDC_INVENTORY/ioc_hunt_$ts.txt
    IOC_SUSPECT_PIDS=()
    echo "Hunting for indicators of compromise..."
    {
        echo "=== Suspicious processes ==="
        for pid in /proc/[0-9]*; do
            pid=${pid#/proc/}
            [ -r "/proc/$pid/status" ] || continue
            exe=$(readlink "/proc/$pid/exe" 2>/dev/null) || continue
            cwd=$(readlink "/proc/$pid/cwd" 2>/dev/null)
            uid=$(awk '/^Uid:/ {print $2}' "/proc/$pid/status" 2>/dev/null)
            comm=$(cat "/proc/$pid/comm" 2>/dev/null)
            args=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null | cut -c1-160)
            flags=""
            case $exe in /tmp/*|/var/tmp/*|/dev/shm/*|/run/user/*|/home/*/.*) flags+="EXE-IN-TEMP/HIDDEN " ;; esac
            case $exe in *" (deleted)") flags+="DELETED-BINARY " ;; esac
            case $cwd in /tmp*|/var/tmp*|/dev/shm*) flags+="CWD-TEMP " ;; esac
            if [ -n "$uid" ] && [ "$uid" -gt 0 ] && [ "$uid" -lt 1000 ]; then
                case $comm in bash|sh|dash|zsh|ksh|ash|python*|perl|ruby|php|nc|ncat|netcat|socat|telnet)
                    flags+="SERVICE-ACCOUNT-SHELL " ;;
                esac
            fi
            case $args in *"/dev/tcp/"*|*"bash -i"*|*"nc -e"*|*"ncat -e"*|*mkfifo*|*"pty.spawn"*|*linpeas*|*pspy*|*chisel*|*ligolo*)
                flags+="REVSHELL/TOOLING-ARGS " ;;
            esac
            [ -n "$flags" ] || continue
            user=$(awk -F: -v u="$uid" '$3==u {print $1; exit}' /etc/passwd)
            echo "PID $pid user=${user:-$uid} exe=$exe :: $flags"
            echo "    cmd: $args"
            IOC_SUSPECT_PIDS+=("$pid")
        done
        [ ${#IOC_SUSPECT_PIDS[@]} -eq 0 ] && echo "  none"

        echo; echo "=== Unexpected listeners (not README-needed, not 22/111) ==="
        local expected port any=0
        expected=$(_expected_ports)
        for port in $(listening_ports); do
            in_list "$port" $expected && continue
            any=1
            echo "  port $port: $(list_listening | grep -E "[:.]${port}[[:space:]]" | head -2 | tr -s ' ')"
        done
        [ "$any" = 0 ] && echo "  none"

        echo; echo "=== Executables in temp dirs ==="
        find /tmp /var/tmp /dev/shm -xdev -type f \( -perm -0100 -o -perm -0010 -o -perm -0001 \) 2>/dev/null | head -n 50 | while read -r f; do ls -l "$f"; done
        find /tmp /var/tmp /dev/shm -xdev -type f -size -20M 2>/dev/null | while read -r f; do
            [ "$(head -c 4 "$f" 2>/dev/null | od -An -c 2>/dev/null | tr -d ' ')" = "177ELF" ] && echo "  ELF binary: $f"
        done

        echo; echo "=== Known red-team tooling on disk ==="
        find /tmp /var/tmp /dev/shm /root /home /opt /var/www -maxdepth 4 -type f \
            \( -iname 'linpeas*' -o -iname 'linenum*' -o -iname 'lse.sh' -o -iname 'pspy*' -o -iname 'chisel*' \
               -o -iname 'ligolo*' -o -iname '*.elf' -o -iname 'sliver*' -o -iname 'meterpreter*' -o -iname 'beacon*' \) 2>/dev/null | head -n 50

        echo; echo "=== Recon commands in shell histories (whoami / sudo -l / id / enumeration) ==="
        local h
        while IFS=: read -r user _ _ _ _ h _; do
            for f in "$h/.bash_history" "$h/.zsh_history" "$h/.sh_history" "$h/.ash_history"; do
                [ -f "$f" ] || continue
                grep -HnE '(^|[;& ])(whoami|sudo -l|id$|uname -a|cat /etc/(passwd|shadow)|find / -perm|getcap|linpeas|wget|curl .*\| *sh|nc |/dev/tcp)' "$f" 2>/dev/null | tail -n 8
            done
        done < /etc/passwd

        echo; echo "=== 'sudo -l' / failed sudo in auth logs (last 20) ==="
        grep -hE 'COMMAND=list|incorrect password attempts|NOT in sudoers' /var/log/auth.log /var/log/secure 2>/dev/null | tail -n 20
        have journalctl && journalctl -q --no-pager -n 400 _COMM=sudo 2>/dev/null | grep -E 'COMMAND=list|incorrect password|NOT in sudoers' | tail -n 20
    } > "$report" 2>&1
    cat "$report"
    log "IOC hunt written: $report (${#IOC_SUSPECT_PIDS[@]} suspicious PIDs)"
}

# containment -> eradication -> recovery, one PID at a time (interactive only)
ioc_respond() {
    ccdc_noninteractive && { echo "ioc_respond is interactive only."; return 0; }
    local pid=${1:-} choice exe dest
    if [ -z "$pid" ]; then
        [ ${#IOC_SUSPECT_PIDS[@]} -gt 0 ] || ioc_hunt >/dev/null
        [ ${#IOC_SUSPECT_PIDS[@]} -gt 0 ] || { echo "No suspicious PIDs found."; return 0; }
        echo "Suspicious PIDs: ${IOC_SUSPECT_PIDS[*]}"
        read -r -p "PID to respond to (blank = cancel): " pid || return 0
        [ -n "$pid" ] || return 0
    fi
    [ -d "/proc/$pid" ] || { echo "PID $pid is gone."; return 0; }
    ps -o pid,ppid,user,etime,args -p "$pid" 2>/dev/null || cat "/proc/$pid/cmdline" | tr '\0' ' '
    echo "Open network sockets:"; (ss -tunp 2>/dev/null || netstat -tunp 2>/dev/null) | grep "pid=$pid," | sed 's/^/  /'
    echo " s) CONTAIN - freeze it (SIGSTOP), keeps memory/evidence"
    echo " k) ERADICATE - quarantine a copy of its binary, then kill -9"
    echo " c) CONTINUE a frozen process (SIGCONT)"
    echo " n) nothing"
    read -r -p "Choice: " choice || return 0
    case $choice in
        s) kill -STOP "$pid" && log "CONTAINED (SIGSTOP) pid $pid" ;;
        k) exe=$(readlink "/proc/$pid/exe" 2>/dev/null)
           dest=$CCDC_QUARANTINE/pid${pid}_$(basename "${exe%% (deleted)}" 2>/dev/null)
           cp "/proc/$pid/exe" "$dest" 2>/dev/null && chmod 000 "$dest" && log "Quarantined binary of pid $pid ($exe) -> $dest"
           kill -9 "$pid" && log "ERADICATED (kill -9) pid $pid"
           echo "Recovery: find how it started (03_persistence.sh scan), check the scored service it touched, re-run 07." ;;
        c) kill -CONT "$pid" && log "Resumed pid $pid" ;;
        *) echo "No action." ;;
    esac
}

discovery_auto() {
    hunt_local_ports
    ioc_hunt
    if ask "Run full nmap enumeration of this host/subnet now?" CCDC_DISCOVERY_NMAP no; then
        enumerate_nmap
    fi
    return 0
}

discovery_actions() {
    cat <<'EOF'
  auto      local port hunt -> IOC hunt -> nmap (optional, CCDC_DISCOVERY_NMAP)
  ports     fast local port hunt (from enumeration.sh)
  nmap      full nmap enumeration (from enumeration.sh)
  ioc       IOC hunt (processes, temp binaries, tooling, recon commands, unexpected listeners)
  respond   contain / eradicate a suspicious PID (interactive)
EOF
}

discovery_run_action() {
    case $1 in
        auto) discovery_auto ;;
        ports) hunt_local_ports ;;
        nmap) enumerate_nmap ;;
        ioc) ioc_hunt ;;
        respond) ioc_respond ;;
        *) err "Unknown action: $1"; discovery_actions; return 2 ;;
    esac
}

discovery_menu() {
    ccdc_menu "07_discovery.sh - Discovery / Threat Hunt" \
        "Run all (port hunt -> IOC hunt -> optional nmap)" discovery_auto \
        "Fast local port hunt" hunt_local_ports \
        "Full nmap enumeration" enumerate_nmap \
        "IOC hunt" ioc_hunt \
        "Respond to a suspicious PID (contain/eradicate)" ioc_respond
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    ccdc_main discovery "$@"
fi
