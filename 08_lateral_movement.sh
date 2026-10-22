#!/usr/bin/env bash
# =====================================================================
#  08_lateral_movement.sh - INGRESS firewall (default-deny, README-driven
#  allowlist), firewall reload helper, kernel/network sysctl hardening.
#  ATT&CK: Lateral Movement (TA0008). Egress lives in 09_c2_and_exfil.sh.
#  Backend order: nftables -> ufw -> firewalld -> iptables.
#  After ANY manual firewall change run: sudo bash 08_lateral_movement.sh --run save
# =====================================================================
[ -n "${BASH_VERSION:-}" ] || { echo "Run with bash: sudo bash $0" >&2; exit 1; }
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh" || { echo "common.sh missing next to $0" >&2; exit 1; }

FW_IN_TCP=()
FW_IN_UDP=()
FW_KEEP_FORWARD=""
FW_ALLOW_PING=""

host_forwards_traffic() {
    [ "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)" = 1 ] && return 0
    have docker || have podman || have lxc-ls || have virsh || [ -d /var/lib/docker ]
}

forwarding_decision() {
    [ -n "$FW_KEEP_FORWARD" ] && return 0
    FW_KEEP_FORWARD=no
    if host_forwards_traffic; then
        warn "This host forwards traffic or runs containers/VMs (ip_forward=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null))."
        warn "Dropping FORWARD / ip_forward=0 will cut off containers - scored services inside them go down."
        ask "Keep packet forwarding allowed?" CCDC_KEEP_FORWARDING yes && FW_KEEP_FORWARD=yes
    fi
    log "Forwarding kept: $FW_KEEP_FORWARD"
}

_split_ports() { echo "${1:-}" | tr ',' ' '; }

# build FW_IN_TCP / FW_IN_UDP from README answers + extras + safety rails
fw_ingress_ports() {
    readme_services || return 1
    FW_IN_TCP=(); FW_IN_UDP=()
    [ "${need[ssh]:-no}" = "yes" ] && FW_IN_TCP+=(22)
    [ "${need[web]:-no}" = "yes" ] && FW_IN_TCP+=(80 443)
    [ "${need[ftp]:-no}" = "yes" ] && FW_IN_TCP+=(21)
    [ "${need[dns]:-no}" = "yes" ] && { FW_IN_TCP+=(53); FW_IN_UDP+=(53); }
    [ "${need[mail]:-no}" = "yes" ] && FW_IN_TCP+=(25 143 993 995)
    [ "${need[samba]:-no}" = "yes" ] && { FW_IN_TCP+=(139 445); FW_IN_UDP+=(137 138); }
    if [ "${need[mysql]:-no}" = "yes" ] && ask "Must MySQL (3306) accept connections from OTHER hosts? (no = local only)" CCDC_MYSQL_REMOTE no; then
        FW_IN_TCP+=(3306)
    fi
    if [ "${need[postgres]:-no}" = "yes" ] && ask "Must PostgreSQL (5432) accept connections from OTHER hosts? (no = local only)" CCDC_POSTGRES_REMOTE no; then
        FW_IN_TCP+=(5432)
    fi
    local p
    for p in $(_split_ports "${CCDC_EXTRA_TCP_IN:-}"); do FW_IN_TCP+=("$p"); done
    for p in $(_split_ports "${CCDC_EXTRA_UDP_IN:-}"); do FW_IN_UDP+=("$p"); done
    if [ "${need[ftp]:-no}" = "yes" ] && [ -n "${CCDC_FTP_PASV_RANGE:-}" ]; then FW_IN_TCP+=("$CCDC_FTP_PASV_RANGE"); fi

    if [ -n "${SSH_CONNECTION:-}" ] && ! in_list 22 "${FW_IN_TCP[@]}"; then
        warn "You are connected over SSH but the README says no ssh - new SSH sessions would be blocked."
        ask "Keep TCP 22 open so you can get back in?" CCDC_KEEP_SSH_FOR_ADMIN yes && FW_IN_TCP+=(22)
    fi
    if [ -z "$FW_ALLOW_PING" ]; then
        FW_ALLOW_PING=no
        ask "Allow inbound ping (ICMP echo)? Many scoring engines check it." CCDC_ALLOW_PING yes && FW_ALLOW_PING=yes
    fi
    log "Ingress allowlist: tcp=[${FW_IN_TCP[*]:-}] udp=[${FW_IN_UDP[*]:-}] ping=$FW_ALLOW_PING"
}

_nft_set() { local IFS=,; echo "{ $* }"; }

stop_competing_firewalls() {
    local b=$1 s
    for s in firewalld ufw; do
        [ "$s" = "$b" ] && continue
        [ "$b" = firewalld ] && [ "$s" = firewalld ] && continue
        if svc_is_active "$s" 2>/dev/null; then
            warn "$s is active and will fight the $b ruleset (watchdog flapping)."
            if ask "Stop + disable $s?" CCDC_STOP_OTHER_FIREWALLS yes; then
                [ "$s" = ufw ] && ufw --force disable >/dev/null 2>&1
                svc_stop_disable "$s" && log "Stopped + disabled $s"
            fi
        fi
    done
}

# fw_backup_pre BACKEND LABEL - snapshot the ruleset before we touch it
fw_backup_pre() {
    local b=$1 label=$2 out
    out=$CCDC_BACKUPS/firewall_pre_${label}_$(date +%Y%m%d_%H%M%S)
    mkdir -p "$out"
    case $b in
        nft)       nft list ruleset > "$out/nftables.txt" 2>&1 ;;
        iptables)  have iptables-save && iptables-save > "$out/iptables.rules" 2>&1
                   have ip6tables-save && ip6tables-save > "$out/ip6tables.rules" 2>&1 ;;
        ufw)       ufw status verbose > "$out/ufw_status.txt" 2>&1
                   [ -d /etc/ufw ] && tar -czf "$out/etc_ufw.tar.gz" -C / etc/ufw 2>/dev/null ;;
        firewalld) firewall-cmd --list-all-zones > "$out/zones.txt" 2>&1
                   firewall-cmd --direct --get-all-rules > "$out/direct.txt" 2>&1
                   [ -d /etc/firewalld ] && tar -czf "$out/etc_firewalld.tar.gz" -C / etc/firewalld 2>/dev/null ;;
    esac
    log "Pre-change firewall ruleset saved -> $out"
}

fw_ingress_nft() {
    local t fwd=drop
    [ "$FW_KEEP_FORWARD" = yes ] && fwd=accept
    # drop every table except our egress table (09); keep them all when containers need their NAT/forward rules
    if [ "$FW_KEEP_FORWARD" = yes ]; then
        nft delete table inet ccdc 2>/dev/null
        warn "Forwarding kept - existing nft tables (container NAT etc.) left in place. Review: nft list ruleset"
    else
        while read -r t; do
            [ -n "$t" ] || continue
            [ "$t" = "inet ccdc_egress" ] && continue
            # shellcheck disable=SC2086
            nft delete table $t 2>/dev/null
        done < <(nft list tables 2>/dev/null | awk '{print $2" "$3}')
    fi
    nft add table inet ccdc
    nft add chain inet ccdc input '{ type filter hook input priority 0 ; policy drop ; }'
    nft add chain inet ccdc forward "{ type filter hook forward priority 0 ; policy $fwd ; }"
    nft add rule inet ccdc input iif lo accept
    nft add rule inet ccdc input ct state established,related accept
    nft add rule inet ccdc input ct state invalid drop
    nft add rule inet ccdc input icmpv6 type '{ nd-neighbor-solicit, nd-neighbor-advert, nd-router-advert, nd-router-solicit }' accept
    [ "$FW_ALLOW_PING" = yes ] && { nft add rule inet ccdc input icmp type echo-request accept; nft add rule inet ccdc input icmpv6 type echo-request accept; }
    [ ${#FW_IN_TCP[@]} -gt 0 ] && nft add rule inet ccdc input tcp dport "$(_nft_set "${FW_IN_TCP[@]//:/-}")" accept
    [ ${#FW_IN_UDP[@]} -gt 0 ] && nft add rule inet ccdc input udp dport "$(_nft_set "${FW_IN_UDP[@]//:/-}")" accept
    nft add rule inet ccdc input limit rate 10/minute log prefix '"CCDC-IN-DROP "'
    [ "$fwd" = drop ] && nft add rule inet ccdc forward limit rate 10/minute log prefix '"CCDC-FWD-DROP "'
    log "nftables ingress policy applied (default DROP inbound, forward=$fwd)"
}

fw_ingress_ufw() {
    local p out=allow
    [ -f "$CCDC_STATE/egress_applied" ] && out=deny
    ufw --force reset >/dev/null
    ufw default deny incoming
    ufw default "$out" outgoing
    ufw logging on
    for p in ${FW_IN_TCP[@]+"${FW_IN_TCP[@]}"}; do ufw allow "$p/tcp" >/dev/null; done
    for p in ${FW_IN_UDP[@]+"${FW_IN_UDP[@]}"}; do ufw allow "$p/udp" >/dev/null; done
    if [ "$out" = deny ] && [ -f "$CCDC_STATE/ufw_egress_rules" ]; then
        while read -r p; do [ -n "$p" ] && ufw $p >/dev/null; done < "$CCDC_STATE/ufw_egress_rules"
        log "Re-applied saved egress rules from 09"
    fi
    ufw --force enable
    log "ufw ingress policy applied (default DENY incoming, outgoing=$out)"
}

fw_ingress_firewalld() {
    local p ifc
    svc_enable_now firewalld
    firewall-cmd --set-default-zone=drop >/dev/null
    for ifc in /sys/class/net/*; do
        ifc=${ifc##*/}
        [ "$ifc" = lo ] || [ "$ifc" = "*" ] && continue
        firewall-cmd --permanent --zone=drop --change-interface="$ifc" >/dev/null 2>&1
    done
    for p in ${FW_IN_TCP[@]+"${FW_IN_TCP[@]}"}; do firewall-cmd --permanent --zone=drop --add-port="${p//:/-}/tcp" >/dev/null; done
    for p in ${FW_IN_UDP[@]+"${FW_IN_UDP[@]}"}; do firewall-cmd --permanent --zone=drop --add-port="${p//:/-}/udp" >/dev/null; done
    [ "$FW_ALLOW_PING" = yes ] && firewall-cmd --permanent --zone=drop --add-rich-rule='rule protocol value="icmp" accept' >/dev/null 2>&1
    [ "$FW_KEEP_FORWARD" = yes ] && firewall-cmd --permanent --zone=drop --add-forward >/dev/null 2>&1
    firewall-cmd --reload >/dev/null
    log "firewalld ingress policy applied (default zone: drop)"
}

fw_ingress_iptables() {
    local T p fwd=DROP icmp
    [ "$FW_KEEP_FORWARD" = yes ] && fwd=ACCEPT
    for T in iptables ip6tables; do
        have "$T" || continue
        icmp=icmp; [ "$T" = ip6tables ] && icmp=ipv6-icmp
        $T -F INPUT; $T -F FORWARD
        $T -P INPUT DROP
        $T -P FORWARD "$fwd"
        $T -A INPUT -i lo -j ACCEPT
        $T -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
        [ "$T" = ip6tables ] && $T -A INPUT -p ipv6-icmp -j ACCEPT
        [ "$T" = iptables ] && [ "$FW_ALLOW_PING" = yes ] && $T -A INPUT -p icmp --icmp-type echo-request -j ACCEPT
        for p in ${FW_IN_TCP[@]+"${FW_IN_TCP[@]}"}; do $T -A INPUT -p tcp --dport "$p" -j ACCEPT; done
        for p in ${FW_IN_UDP[@]+"${FW_IN_UDP[@]}"}; do $T -A INPUT -p udp --dport "$p" -j ACCEPT; done
        $T -A INPUT -m limit --limit 10/min -j LOG --log-prefix "CCDC-IN-DROP " 2>/dev/null
    done
    log "iptables ingress policy applied (default DROP inbound, forward=$fwd)"
}

# saved ruleset is what the watchdog restores if red team flushes the firewall
fw_save_state() {
    local b
    b=$(fw_detect_backend)
    echo "$b" > "$CCDC_STATE/firewall_backend"
    case $b in
        nft)
            { echo "flush ruleset"; nft list ruleset; } > "$CCDC_STATE/firewall.nft"
            nft list ruleset > "$CCDC_BACKUPS/nftables_ruleset.txt" ;;
        iptables)
            have iptables-save && iptables-save > "$CCDC_STATE/iptables.rules" && cp "$CCDC_STATE/iptables.rules" "$CCDC_BACKUPS/iptables_rules.v4"
            have ip6tables-save && ip6tables-save > "$CCDC_STATE/ip6tables.rules" ;;
        ufw) ufw status verbose > "$CCDC_BACKUPS/ufw_status.txt" 2>&1 ;;
        firewalld) firewall-cmd --list-all-zones > "$CCDC_BACKUPS/firewalld_zones.txt" 2>&1 ;;
    esac
    fw_signature "$b" | cksum > "$CCDC_STATE/fw_signature.cksum"
    log "Firewall state saved ($b) -> $CCDC_STATE"
}

write_firewall_reload_helper() {
    local helper=/usr/local/sbin/ccdc_firewall_reload.sh
    mkdir -p /usr/local/sbin
    cat > "$helper" <<EOF
#!/bin/sh
# generated by 08_lateral_movement.sh - restores the last saved CCDC ruleset, never prompts
STATE="$CCDC_STATE"
BACKEND=\$(cat "\$STATE/firewall_backend" 2>/dev/null)
case "\$BACKEND" in
    nft)       [ -f "\$STATE/firewall.nft" ] && nft -f "\$STATE/firewall.nft" ;;
    iptables)  [ -f "\$STATE/iptables.rules" ] && iptables-restore < "\$STATE/iptables.rules"
               [ -f "\$STATE/ip6tables.rules" ] && command -v ip6tables-restore >/dev/null 2>&1 && ip6tables-restore < "\$STATE/ip6tables.rules" ;;
    ufw)       ufw --force enable ;;
    firewalld) (systemctl start firewalld || rc-service firewalld start || service firewalld start) >/dev/null 2>&1; firewall-cmd --reload ;;
    *)         echo "ccdc_firewall_reload: no saved CCDC firewall state in \$STATE" >&2; exit 1 ;;
esac
echo "\$(date) -- ccdc_firewall_reload restored \$BACKEND ruleset"
EOF
    chmod 700 "$helper"
    log "Firewall reload helper installed: $helper"
}

firewall_ingress() {
    fw_ingress_ports || { err "Firewall not applied: no README answers."; return 1; }
    forwarding_decision
    local b
    b=$(fw_detect_backend)
    log "Applying ingress firewall policy via $b"
    fw_backup_pre "$b" ingress
    stop_competing_firewalls "$b"
    case $b in
        nft) fw_ingress_nft ;;
        ufw) fw_ingress_ufw ;;
        firewalld) fw_ingress_firewalld ;;
        iptables) fw_ingress_iptables ;;
        *) err "No firewall tool found (nft/ufw/firewalld/iptables). Install one (e.g. pkg nftables) and re-run."; return 1 ;;
    esac
    touch "$CCDC_STATE/ingress_applied"
    fw_save_state
    [ -x /usr/local/sbin/ccdc_firewall_reload.sh ] || write_firewall_reload_helper
    echo ">>> Test a NEW ssh session / scored service from another host before you walk away. <<<"
}

firewall_show() {
    case $(fw_detect_backend) in
        nft) nft list ruleset ;;
        ufw) ufw status verbose ;;
        firewalld) firewall-cmd --list-all-zones | sed -n '/(active)/,/^$/p' ;;
        iptables) iptables -L -n -v --line-numbers; have ip6tables && ip6tables -L -n --line-numbers ;;
        *) echo "No firewall tool found." ;;
    esac
}

kernel_hardening() {
    [ -f /etc/sysctl.conf ] || touch /etc/sysctl.conf
    backup_file /etc/sysctl.conf
    forwarding_decision
    local settings=(
        "net.ipv4.tcp_syncookies=1"
        "net.ipv4.conf.all.rp_filter=1"
        "net.ipv4.conf.default.rp_filter=1"
        "net.ipv4.conf.all.accept_redirects=0"
        "net.ipv4.conf.default.accept_redirects=0"
        "net.ipv4.conf.all.send_redirects=0"
        "net.ipv4.conf.default.send_redirects=0"
        "net.ipv4.conf.all.accept_source_route=0"
        "net.ipv4.conf.all.log_martians=1"
        "net.ipv4.icmp_echo_ignore_broadcasts=1"
        "kernel.randomize_va_space=2"
    )
    [ "$FW_KEEP_FORWARD" = yes ] || settings=("net.ipv4.ip_forward=0" "${settings[@]}")
    local item
    for item in "${settings[@]}"; do
        set_line /etc/sysctl.conf "${item%%=*}" " = " "${item#*=}"
    done
    sysctl --system >/dev/null 2>&1
    sysctl -p /etc/sysctl.conf >/dev/null 2>&1
    log "Kernel/network hardening applied (ip_forward left alone: $FW_KEEP_FORWARD)"
}

lateral_movement_auto() {
    write_firewall_reload_helper
    firewall_ingress || true
    kernel_hardening
    return 0
}

lateral_movement_actions() {
    cat <<'EOF'
  auto      reload helper -> ingress firewall -> kernel sysctl hardening
  firewall  ingress firewall only (default-deny inbound, README allowlist)
  kernel    sysctl anti-spoofing / anti-redirect hardening
  save      snapshot the CURRENT ruleset as the one the watchdog restores
  helper    (re)write /usr/local/sbin/ccdc_firewall_reload.sh
  show      print current firewall rules
EOF
}

lateral_movement_run_action() {
    case $1 in
        auto) lateral_movement_auto ;;
        firewall) firewall_ingress ;;
        kernel) kernel_hardening ;;
        save) fw_save_state ;;
        helper) write_firewall_reload_helper ;;
        show) firewall_show ;;
        *) err "Unknown action: $1"; lateral_movement_actions; return 2 ;;
    esac
}

lateral_movement_menu() {
    ccdc_menu "08_lateral_movement.sh - Lateral Movement (ingress firewall + sysctl)" \
        "Run all" lateral_movement_auto \
        "Ingress firewall (default-deny, README allowlist)" firewall_ingress \
        "Kernel/network hardening (sysctl)" kernel_hardening \
        "Save current ruleset for the watchdog" fw_save_state \
        "Show firewall rules" firewall_show
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    ccdc_main lateral_movement "$@"
fi
