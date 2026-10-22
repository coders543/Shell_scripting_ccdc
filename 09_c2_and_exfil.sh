#!/usr/bin/env bash
# =====================================================================
#  09_c2_and_exfil.sh - EGRESS firewall (default-deny outbound, only
#  DNS/web/NTP + README needs) and an outbound-connection hunt against
#  the malware/C2 watchlist.
#  ATT&CK: Command and Control (TA0011) + Exfiltration (TA0010).
#  Runs after 08_lateral_movement.sh but works standalone.
# =====================================================================
[ -n "${BASH_VERSION:-}" ] || { echo "Run with bash: sudo bash $0" >&2; exit 1; }
_ccdc_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
. "$_ccdc_dir/common.sh" || { echo "common.sh missing next to $0" >&2; exit 1; }
. "$_ccdc_dir/08_lateral_movement.sh" || { echo "08_lateral_movement.sh missing next to $0" >&2; exit 1; }

FW_OUT_TCP=()
FW_OUT_UDP=()

# outbound sockets: "proto state local peer process"
_outbound_sockets() {
    local listen
    listen=" $(listening_ports | tr '\n' ' ') "
    if have ss; then
        ss -tunp 2>/dev/null | awk 'NR>1 && $2 != "LISTEN" && $2 != "UNCONN" {print $1, $2, $5, $6, $7}'
    else
        netstat -tunp 2>/dev/null | awk '$1 ~ /^(tcp|udp)/ && $6 != "LISTEN" {print $1, ($6 ~ /\//) ? "-" : $6, $4, $5, $NF}'
    fi | while read -r proto state lcl peer proc; do
        local lport=${lcl##*:} rport=${peer##*:}
        case "$peer" in *'*'*|0.0.0.0:*|'[::]:'*) continue ;; esac
        case $listen in *" $lport "*) continue ;; esac
        echo "$proto $state $lcl $peer $rport ${proc:--}"
    done
}

# baseline allowlist, never prompts
fw_egress_baseline() {
    readme_load_saved || true
    FW_OUT_TCP=(53 80 443)
    FW_OUT_UDP=(53 123)
    [ "${need[mail]:-no}" = yes ] && FW_OUT_TCP+=(25 587)
    local p
    for p in $(_split_ports "${CCDC_EXTRA_TCP_OUT:-}"); do FW_OUT_TCP+=("$p"); done
    for p in $(_split_ports "${CCDC_EXTRA_UDP_OUT:-}"); do FW_OUT_UDP+=("$p"); done
}

fw_egress_ports() {
    readme_services || warn "No README answers - egress uses the baseline allowlist only."
    fw_egress_baseline

    # existing outbound dependencies that egress would break (web->remote DB, LDAP to DC...)
    local proto state lcl peer rport proc seen=" "
    while read -r proto state lcl peer rport proc; do
        [ -n "$rport" ] || continue
        case $proto in tcp*) in_list "$rport" "${FW_OUT_TCP[@]}" && continue ;; *) in_list "$rport" "${FW_OUT_UDP[@]}" && continue ;; esac
        case $seen in *" $proto/$rport "*) continue ;; esac
        seen+="$proto/$rport "
        local tag=""
        [ -n "${MALWARE_PORT_WATCHLIST[$rport]:-}" ] && tag=" [WATCHLIST: ${MALWARE_PORT_WATCHLIST[$rport]%%|*}]"
        warn "Live outbound $proto to $peer ($proc) is NOT in the egress allowlist$tag - it will be blocked for new connections."
        if [ -z "$tag" ] && ! ccdc_noninteractive && ask "  Allow outbound $proto/$rport (only if this is a real dependency of a scored service)?"; then
            case $proto in tcp*) FW_OUT_TCP+=("$rport") ;; *) FW_OUT_UDP+=("$rport") ;; esac
        fi
    done < <(_outbound_sockets)
    log "Egress allowlist: tcp=[${FW_OUT_TCP[*]}] udp=[${FW_OUT_UDP[*]}]"
}

fw_egress_nft() {
    local sp=()
    nft delete table inet ccdc_egress 2>/dev/null
    nft add table inet ccdc_egress
    nft add chain inet ccdc_egress output '{ type filter hook output priority 0 ; policy drop ; }'
    nft add rule inet ccdc_egress output oif lo accept
    nft add rule inet ccdc_egress output ct state established,related accept
    nft add rule inet ccdc_egress output icmpv6 type '{ nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit }' accept
    nft add rule inet ccdc_egress output tcp dport "$(_nft_set "${FW_OUT_TCP[@]//:/-}")" accept
    nft add rule inet ccdc_egress output udp dport "$(_nft_set "${FW_OUT_UDP[@]//:/-}")" accept
    [ "${need[ssh]:-no}" = yes ] && sp+=(22)
    [ "${need[web]:-no}" = yes ] && sp+=(80 443)
    [ ${#sp[@]} -gt 0 ] && nft add rule inet ccdc_egress output tcp sport "$(_nft_set "${sp[@]}")" accept
    nft add rule inet ccdc_egress output limit rate 10/minute log prefix '"CCDC-OUT-DROP "'
    log "nftables egress policy applied (default DROP outbound)"
}

fw_egress_ufw() {
    local p rules=$CCDC_STATE/ufw_egress_rules
    : > "$rules"
    for p in "${FW_OUT_TCP[@]}"; do echo "allow out $p/tcp" >> "$rules"; done
    for p in "${FW_OUT_UDP[@]}"; do echo "allow out $p/udp" >> "$rules"; done
    ufw default deny outgoing
    while read -r p; do ufw $p >/dev/null; done < "$rules"
    ufw --force enable
    log "ufw egress policy applied (default DENY outgoing)"
}

fw_egress_firewalld() {
    local fam p
    svc_enable_now firewalld
    for fam in ipv4 ipv6; do
        firewall-cmd --permanent --direct --remove-rules "$fam" filter OUTPUT >/dev/null 2>&1
        firewall-cmd --permanent --direct --add-rule "$fam" filter OUTPUT 0 -o lo -j ACCEPT >/dev/null
        firewall-cmd --permanent --direct --add-rule "$fam" filter OUTPUT 0 -m state --state ESTABLISHED,RELATED -j ACCEPT >/dev/null
        [ "$fam" = ipv6 ] && firewall-cmd --permanent --direct --add-rule ipv6 filter OUTPUT 0 -p ipv6-icmp -j ACCEPT >/dev/null
        for p in "${FW_OUT_TCP[@]}"; do firewall-cmd --permanent --direct --add-rule "$fam" filter OUTPUT 1 -p tcp --dport "$p" -j ACCEPT >/dev/null; done
        for p in "${FW_OUT_UDP[@]}"; do firewall-cmd --permanent --direct --add-rule "$fam" filter OUTPUT 1 -p udp --dport "$p" -j ACCEPT >/dev/null; done
        firewall-cmd --permanent --direct --add-rule "$fam" filter OUTPUT 9 -j DROP >/dev/null
    done
    firewall-cmd --reload >/dev/null
    log "firewalld egress policy applied via direct rules (default DROP outbound)"
}

fw_egress_iptables() {
    local T p
    for T in iptables ip6tables; do
        have "$T" || continue
        $T -F OUTPUT
        $T -P OUTPUT DROP
        $T -A OUTPUT -o lo -j ACCEPT
        $T -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
        [ "$T" = ip6tables ] && $T -A OUTPUT -p ipv6-icmp -j ACCEPT
        for p in "${FW_OUT_TCP[@]}"; do $T -A OUTPUT -p tcp --dport "$p" -j ACCEPT; done
        for p in "${FW_OUT_UDP[@]}"; do $T -A OUTPUT -p udp --dport "$p" -j ACCEPT; done
        $T -A OUTPUT -m limit --limit 10/min -j LOG --log-prefix "CCDC-OUT-DROP " 2>/dev/null
    done
    log "iptables egress policy applied (default DROP outbound)"
}

firewall_egress() {
    fw_egress_ports
    local b
    b=$(fw_detect_backend)
    log "Applying egress firewall policy via $b"
    fw_backup_pre "$b" egress
    case $b in
        nft) fw_egress_nft ;;
        ufw) fw_egress_ufw ;;
        firewalld) fw_egress_firewalld ;;
        iptables) fw_egress_iptables ;;
        *) err "No firewall tool found (nft/ufw/firewalld/iptables). Install one and re-run."; return 1 ;;
    esac
    touch "$CCDC_STATE/egress_applied"
    fw_save_state
    [ -x /usr/local/sbin/ccdc_firewall_reload.sh ] || write_firewall_reload_helper
    [ -f "$CCDC_STATE/ingress_applied" ] || warn "Ingress firewall (08_lateral_movement.sh) has not been applied on this box yet."
    echo "NOTE: connections that were already open survive via conntrack - run the egress hunt and kill anything shady."
}

egress_watchlist_hunt() {
    fw_egress_baseline
    echo "Outbound connections right now (this host is the client):"
    local proto state lcl peer rport proc any=0 tag
    while read -r proto state lcl peer rport proc; do
        any=1
        tag=""
        [ -n "${MALWARE_PORT_WATCHLIST[$rport]:-}" ] && tag="[MALWARE/C2: ${MALWARE_PORT_WATCHLIST[$rport]%%|*}] "
        [ -n "${PORT_WATCHLIST[$rport]:-}" ] && [ -z "$tag" ] && tag="[HIGH-VALUE: ${PORT_WATCHLIST[$rport]%%|*}] "
        case $proto in
            tcp*) in_list "$rport" "${FW_OUT_TCP[@]}" || tag+="[NOT-IN-EGRESS-ALLOWLIST] " ;;
            *)    in_list "$rport" "${FW_OUT_UDP[@]}" || tag+="[NOT-IN-EGRESS-ALLOWLIST] " ;;
        esac
        printf '  %-5s %-11s %-22s -> %-24s %s %s\n' "$proto" "$state" "$lcl" "$peer" "$proc" "$tag"
    done < <(_outbound_sockets)
    [ "$any" = 0 ] && echo "  none"
    echo
    echo "Anything tagged above: identify the PID, then contain/kill it with 07_discovery.sh --run respond"
    log "Egress watchlist hunt complete"
}

c2_exfil_auto() {
    egress_watchlist_hunt
    firewall_egress || true
    return 0
}

c2_exfil_actions() {
    cat <<'EOF'
  auto      outbound hunt -> egress firewall
  firewall  egress firewall only (default-deny outbound)
  hunt      outbound connections vs. malware/C2 watchlist and egress allowlist
EOF
}

c2_exfil_run_action() {
    case $1 in
        auto) c2_exfil_auto ;;
        firewall) firewall_egress ;;
        hunt) egress_watchlist_hunt ;;
        *) err "Unknown action: $1"; c2_exfil_actions; return 2 ;;
    esac
}

c2_exfil_menu() {
    ccdc_menu "09_c2_and_exfil.sh - Command & Control / Exfiltration (egress)" \
        "Run all (hunt -> egress firewall)" c2_exfil_auto \
        "Egress firewall (default-deny outbound)" firewall_egress \
        "Outbound connection hunt (watchlist)" egress_watchlist_hunt
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    ccdc_main c2_exfil "$@"
fi
