#!/usr/bin/env bash
# =====================================================================
#  02_execution.sh - remove attacker tooling, remediate SUID/SGID and
#  world-writable anomalies, optional noexec on shared tmp mounts.
#  ATT&CK: Execution (TA0002). The SUID/world-writable AUDIT lives in
#  enumeration.sh; this script owns the REMEDIATION.
#  Every permission change is recorded in ~root/ccdc/state/perm_restore.sh
# =====================================================================
[ -n "${BASH_VERSION:-}" ] || { echo "Run with bash: sudo bash $0" >&2; exit 1; }
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh" || { echo "common.sh missing next to $0" >&2; exit 1; }

bad_packages() {
    local bad_list=(netcat netcat-openbsd netcat-traditional ncat nmap-ncat nc gnu-netcat openbsd-netcat
                    cryptcat telnet telnetd telnet-server tftpd tftpd-hpa tftp-server rsh rsh-server
                    nfs-kernel-server xinetd)
    local p found=()
    for p in "${bad_list[@]}"; do pkg_is_installed "$p" && found+=("$p"); done
    if [ ${#found[@]} -eq 0 ]; then
        echo "No attacker-tooling packages installed."
        return 0
    fi
    echo "Installed attacker-tooling/legacy packages: ${found[*]}"
    ask "Remove these packages?" CCDC_REMOVE_BAD_PACKAGES yes || { log "Bad-package removal skipped"; return 0; }
    for p in "${found[@]}"; do
        pkg_remove "$p" && log "Removed $p"
    done
}

# expected SUID/SGID binaries (basename) - anything else gets reviewed
CCDC_SUID_KNOWN_GOOD="passwd sudo sudoedit su mount umount ping ping6 chsh chfn gpasswd newgrp pkexec unix_chkpwd
ssh-keysign dbus-daemon-launch-helper fusermount fusermount3 crontab at chage expiry wall write bsd-write ssh-agent
polkit-agent-helper-1 Xorg.wrap ntfs-3g pppd mount.nfs mount.cifs mount.ecryptfs_private staprun userhelper usernetctl
snap-confine sg newuidmap newgidmap locate mlocate plocate dotlockfile mail-lock utempter chrome-sandbox
traceroute6.iputils pam_timestamp_check lockdev netreport postdrop postqueue mlock screen ksu
VBoxHeadless VBoxNetAdpCtl VBoxNetDHCP VBoxNetNAT VBoxSDL VBoxVolInfo VirtualBoxVM procmail exim4 sendmail
dmcrypt-get-device ssh-keysign gnome-pty-helper vmware-user-suid-wrapper doas"

# GTFOBins-style: SUID on these = instant root shell
CCDC_SUID_DANGEROUS="bash sh dash zsh ksh csh tcsh fish ash busybox find vim vim.basic vim.tiny vi view rvim nano pico ed
python python2 python3 perl ruby lua php node nodejs awk gawk mawk nawk nmap less more man cp mv tar zip unzip gzip env tee
nc ncat netcat socat wget curl base64 xxd od dd gdb strace ltrace taskset nice ionice timeout stdbuf flock docker systemctl
journalctl git sed openssl rsync scp ssh tclsh wish expect watch xargs time make cpulimit chroot install dmesg ip"

_perm_record() {
    local f=$1 mode owner
    mode=$(stat -c '%a' "$f" 2>/dev/null) || return 1
    owner=$(stat -c '%U:%G' "$f" 2>/dev/null)
    echo "chmod $mode '$f'  # was $owner, changed $(date '+%F %T')" >> "$CCDC_STATE/perm_restore.sh"
}

suid_sgid_remediate() {
    local f base report ts high=() review=()
    ts=$(date +%Y%m%d_%H%M%S)
    report=$CCDC_INVENTORY/suid_review_$ts.txt
    echo "Scanning for SUID/SGID binaries (this filesystem only)..."
    while IFS= read -r f; do
        base=$(basename "$f")
        if in_list "$base" $CCDC_SUID_DANGEROUS || [[ $base =~ ^python[0-9.]*$|^perl[0-9.]*$|^php[0-9.]*$|^ruby[0-9.]*$ ]]; then
            high+=("$f")
        elif in_list "$base" $CCDC_SUID_KNOWN_GOOD; then
            :
        else
            review+=("$f")
        fi
    done < <(find / -xdev -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null)

    {
        echo "=== HIGH: SUID/SGID on shell-escape-capable binaries (GTFOBins) ==="
        for f in ${high[@]+"${high[@]}"}; do ls -l "$f"; done
        echo; echo "=== REVIEW: SUID/SGID not on the known-good list ==="
        for f in ${review[@]+"${review[@]}"}; do ls -l "$f"; done
    } > "$report"
    cat "$report"
    log "SUID/SGID review written: $report (${#high[@]} high, ${#review[@]} to review)"

    if [ ${#high[@]} -gt 0 ] && ask "Strip SUID/SGID from the ${#high[@]} HIGH-risk binaries above?" CCDC_STRIP_DANGEROUS_SUID yes; then
        for f in "${high[@]}"; do
            _perm_record "$f" && chmod u-s,g-s "$f" && log "Stripped SUID/SGID: $f"
        done
    fi
    if [ ${#review[@]} -gt 0 ] && ! ccdc_noninteractive && ask "Walk through the ${#review[@]} REVIEW binaries one by one?"; then
        for f in "${review[@]}"; do
            if ask "  Strip SUID/SGID from $f ($(stat -c '%a %U:%G' "$f" 2>/dev/null))?"; then
                _perm_record "$f" && chmod u-s,g-s "$f" && log "Stripped SUID/SGID: $f"
            fi
        done
    fi
    # anything SUID living in a temp dir is almost certainly planted
    find /tmp /var/tmp /dev/shm -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | while read -r f; do
        warn "SUID/SGID file in temp dir: $f - quarantining a copy and stripping the bit"
        cp -a "$f" "$CCDC_QUARANTINE/" 2>/dev/null
        _perm_record "$f" && chmod u-s,g-s "$f"
    done
}

world_writable_remediate() {
    local f files=() dirs=() ts report
    ts=$(date +%Y%m%d_%H%M%S)
    report=$CCDC_INVENTORY/world_writable_review_$ts.txt
    while IFS= read -r f; do files+=("$f"); done < <(find / -xdev -type f -perm -0002 \
        ! -path '/proc/*' ! -path '/sys/*' ! -path '/dev/*' ! -path '/run/*' ! -path '/tmp/*' ! -path '/var/tmp/*' 2>/dev/null)
    while IFS= read -r f; do dirs+=("$f"); done < <(find / -xdev -type d -perm -0002 ! -perm -1000 \
        ! -path '/proc/*' ! -path '/sys/*' ! -path '/dev/*' ! -path '/run/*' 2>/dev/null)
    {
        echo "=== World-writable FILES (outside tmp dirs) ==="
        for f in ${files[@]+"${files[@]}"}; do ls -ld "$f"; done
        echo; echo "=== World-writable DIRECTORIES without sticky bit ==="
        for f in ${dirs[@]+"${dirs[@]}"}; do ls -ld "$f"; done
    } > "$report"
    cat "$report"
    log "World-writable review written: $report (${#files[@]} files, ${#dirs[@]} dirs)"

    if [ ${#files[@]} -gt 0 ] && ask "Remove world-write (o-w) from these ${#files[@]} files? (check web upload paths first)" CCDC_FIX_WORLD_WRITABLE no; then
        for f in "${files[@]}"; do _perm_record "$f" && chmod o-w "$f" && log "o-w: $f"; done
    fi
    if [ ${#dirs[@]} -gt 0 ] && ask "Add the sticky bit (+t) to these ${#dirs[@]} world-writable dirs? (others can no longer delete each other's files)" CCDC_FIX_WORLD_WRITABLE no; then
        for f in "${dirs[@]}"; do _perm_record "$f" && chmod +t "$f" && log "+t: $f"; done
    fi
}

tmp_noexec() {
    local m
    for m in /dev/shm /tmp /var/tmp; do
        grep -qE "[[:space:]]${m}[[:space:]]" /proc/mounts 2>/dev/null || continue
        grep -E "[[:space:]]${m}[[:space:]]" /proc/mounts | grep -q noexec && { echo "$m already noexec"; continue; }
        if ask "Remount $m noexec,nosuid,nodev (runtime only, reverts on reboot)?" CCDC_TMP_NOEXEC no; then
            mount -o remount,noexec,nosuid,nodev "$m" && log "Remounted $m noexec,nosuid,nodev. Undo: mount -o remount,exec $m"
        fi
    done
}

execution_auto() {
    bad_packages
    suid_sgid_remediate
    world_writable_remediate
    tmp_noexec
    return 0
}

execution_actions() {
    cat <<'EOF'
  auto        bad packages -> SUID/SGID remediation -> world-writable remediation -> tmp noexec
  packages    remove attacker tooling (netcat variants, telnet, tftp, rsh, xinetd, nfs server)
  suid        SUID/SGID review + strip on GTFOBins-capable binaries
  writable    world-writable files/dirs review + fix
  noexec      remount /dev/shm, /tmp, /var/tmp noexec (if separate mounts)
EOF
}

execution_run_action() {
    case $1 in
        auto) execution_auto ;;
        packages) bad_packages ;;
        suid) suid_sgid_remediate ;;
        writable) world_writable_remediate ;;
        noexec) tmp_noexec ;;
        *) err "Unknown action: $1"; execution_actions; return 2 ;;
    esac
}

execution_menu() {
    ccdc_menu "02_execution.sh - Execution (attacker tooling / SUID / writable)" \
        "Run all" execution_auto \
        "Bad packages (attacker tooling removal)" bad_packages \
        "SUID/SGID remediation" suid_sgid_remediate \
        "World-writable remediation" world_writable_remediate \
        "noexec on /dev/shm, /tmp, /var/tmp" tmp_noexec
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    ccdc_main execution "$@"
fi
