#!/usr/bin/env bash
# =====================================================================
#  ccdc_orchestrator.sh - thin controller for the CCDC Linux toolkit.
#
#  Interactive (default):  sudo bash ccdc_orchestrator.sh
#  Non-interactive:        sudo bash ccdc_orchestrator.sh --auto [--config ccdc.conf]
#                                [--from STEP] [--only STEP[,STEP]] [--skip STEP[,STEP]]
#
#  Run order (priority override, NOT numeric):
#    enumeration -> passwords -> 01 02 03 04 05 07 08 09 10
#  99_optional_media_games.sh is never run here except by explicit menu choice.
#
#  Exit codes (--auto): 0 ok | 1 setup error | 3 halted after password
#  staging with no TTY (resume with --from 01) | 4 one or more steps failed
# =====================================================================
[ -n "${BASH_VERSION:-}" ] || { echo "Run with bash: sudo bash $0" >&2; exit 1; }
CCDC_ORCH_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
. "$CCDC_ORCH_DIR/common.sh" || { echo "common.sh missing in $CCDC_ORCH_DIR" >&2; exit 1; }

CCDC_STEPS=(enumeration passwords 01_initial_access 02_execution 03_persistence 04_privilege_escalation
            05_defense_evasion_logging 07_discovery 08_lateral_movement 09_c2_and_exfil 10_impact_monitoring)
declare -A STEP_PREFIX=(
    [enumeration]=enumeration [passwords]=passwords [01_initial_access]=initial_access
    [02_execution]=execution [03_persistence]=persistence [04_privilege_escalation]=privilege_escalation
    [05_defense_evasion_logging]=defense_evasion [07_discovery]=discovery
    [08_lateral_movement]=lateral_movement [09_c2_and_exfil]=c2_exfil [10_impact_monitoring]=impact_monitoring
)

for _s in "${CCDC_STEPS[@]}"; do
    # shellcheck disable=SC1090
    . "$CCDC_ORCH_DIR/$_s.sh" || { echo "Missing or broken script: $CCDC_ORCH_DIR/$_s.sh" >&2; exit 1; }
done
unset _s

resolve_step() {
    local want=${1%.sh} s
    for s in "${CCDC_STEPS[@]}"; do
        [ "$want" = "$s" ] && { echo "$s"; return 0; }
        [ "$want" = "${s%%_*}" ] && { echo "$s"; return 0; }
    done
    return 1
}

_resolve_csv() {
    local item out=() r
    for item in $(echo "$1" | tr ',' ' '); do
        r=$(resolve_step "$item") || { err "Unknown step: $item (see --list-steps)"; return 1; }
        out+=("$r")
    done
    echo "${out[*]}"
}

_tty_available() { ( exec </dev/tty ) 2>/dev/null; }

declare -A STEP_RC
run_all() {
    local from="${ORCH_FROM:-}" only="${ORCH_ONLY:-}" skip="${ORCH_SKIP:-}" started=0 step rc failed=0
    [ -z "$from" ] && started=1
    echo "Run order: ${CCDC_STEPS[*]}"
    for step in "${CCDC_STEPS[@]}"; do
        [ "$step" = "$from" ] && started=1
        [ "$started" = 1 ] || continue
        if [ -n "$only" ] && ! in_list "$step" $only; then continue; fi
        if [ -n "$skip" ] && in_list "$step" $skip; then log "Skipping $step (--skip)"; continue; fi

        CCDC_SCRIPT_NAME="$step.sh"
        echo
        echo "################################################################"
        echo "#  STEP: $step.sh"
        echo "################################################################"
        log "=== STEP $step start ==="
        "${STEP_PREFIX[$step]}_auto"
        rc=$?
        CCDC_SCRIPT_NAME=ccdc_orchestrator.sh

        if [ "$step" = passwords ] && [ "$rc" = 10 ]; then
            STEP_RC[$step]="staged (PCR pending)"
            if ccdc_noninteractive; then
                if _tty_available; then
                    echo
                    echo ">>> MANDATORY PAUSE: passwords are staged, NOT applied. PCR CSV: ${CCDC_LAST_PCR_CSV:-$CCDC_PCR}"
                    echo ">>> Hand the CSV to whoever submits the PCR, then press Enter to continue hardening."
                    read -r _ < /dev/tty || true
                else
                    log "HALTED after password staging (no TTY for the mandatory pause)."
                    orch_summary
                    echo
                    echo "HALTED: passwords staged and PCR CSV written (${CCDC_LAST_PCR_CSV:-$CCDC_PCR}). Nothing applied."
                    echo "Resume hardening with:  sudo bash $CCDC_ORCH_DIR/ccdc_orchestrator.sh --auto --from 01"
                    echo "Apply passwords later:  sudo bash $CCDC_ORCH_DIR/passwords.sh --run apply"
                    exit 3
                fi
            fi
            continue
        fi
        if [ "$rc" = 0 ]; then STEP_RC[$step]=ok; else STEP_RC[$step]="FAILED (rc=$rc)"; failed=1; fi
        log "=== STEP $step end (rc=$rc) ==="
    done
    orch_summary
    echo
    echo "Core hardening done. Passwords were NOT changed - staged ones wait in $CCDC_STAGING."
    echo "Apply them after the PCR is acknowledged:  sudo bash $CCDC_ORCH_DIR/passwords.sh --run apply"
    echo "Change log: $LOG | Watchdog log: $CCDC_LOGS/watchdog.log"
    return $((failed * 4))
}

orch_summary() {
    local step
    echo
    echo "==================== RUN SUMMARY ===================="
    for step in "${CCDC_STEPS[@]}"; do
        [ -n "${STEP_RC[$step]:-}" ] && printf '  %-30s %s\n' "$step.sh" "${STEP_RC[$step]}"
    done
    echo "====================================================="
}

user_auditing() {
    rogue_accounts
    lock_root
    uid0_check
    admin_group_reconcile
}

firewall_both() {
    write_firewall_reload_helper
    firewall_ingress && firewall_egress
}

script_menus() {
    local i choice
    for i in "${!CCDC_STEPS[@]}"; do printf ' %2d) %s.sh\n' $((i + 1)) "${CCDC_STEPS[$i]}"; done
    read -r -p "Open which script's menu? " choice || return 0
    if [[ $choice =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le ${#CCDC_STEPS[@]} ]; then
        "${STEP_PREFIX[${CCDC_STEPS[$((choice - 1))]}]}_menu"
    fi
}

show_menu() {
    echo "============================================================"
    echo " CCDC Linux hardening toolkit v$CCDC_VERSION  (detected: $opsys / pkg mgr: ${PKG:-none} / init: $INIT_SYS)"
    echo "============================================================"
    echo " 1) RUN EVERYTHING (enum -> passwords(stage) -> 01..10; nothing applied to passwords)"
    echo " 2) Full nmap enumeration (formatted report, watchlist ports)"
    echo " 3) Fast local port hunt (no scan needed, ss + watchlists)"
    echo " 4) Asset inventory"
    echo " 5) Backups (configs + /tmp + /var runtime dirs)"
    echo " 6) Updates"
    echo " 7) Password policy              8) User auditing"
    echo " 9) Sudoers cleanup              10) Firewall (ingress+egress)"
    echo "11) Kernel hardening             12) File permissions"
    echo "13) Service/SSH hardening        14) Bad packages"
    echo "15) Backdoor/cron review         16) Setup uptime watchdog (every 2 min)"
    echo "17) STAGE password changes + write PCR CSV (does not apply)"
    echo "18) Apply staged password changes (after PCR submitted)"
    echo "------------------- OPTIONAL EXTENSIONS (not in Run Everything) -------------------"
    echo "19) Prohibited media/games sweep (scan + optional delete)"
    echo "------------------------------------------------------------"
    echo "20) Exit"
    echo "21) Per-script menus (IOC hunt, integrity, egress hunt, persistence scan, ...)"
    echo "============================================================"
}

orchestrator_menu() {
    local choice
    while true; do
        show_menu
        read -r -p "Pick an option: " choice || { echo; exit 0; }
        case $choice in
            1)  run_all; pause ;;
            2)  enumerate_nmap; pause ;;
            3)  hunt_local_ports; pause ;;
            4)  asset_inventory; pause ;;
            5)  backup_files; pause ;;
            6)  updates; pause ;;
            7)  password_policy; pause ;;
            8)  user_auditing; pause ;;
            9)  sudoers_stuff; pause ;;
            10) firewall_both; pause ;;
            11) kernel_hardening; pause ;;
            12) file_permissions; pause ;;
            13) service_hardening; pause ;;
            14) bad_packages; pause ;;
            15) backdoors; pause ;;
            16) setup_monitoring; pause ;;
            17) stage_password_changes ;;
            18) apply_staged_passwords; pause ;;
            19) bash "$CCDC_ORCH_DIR/99_optional_media_games.sh"; pause ;;
            20) echo "Bye. Log at $LOG"; exit 0 ;;
            21) script_menus ;;
            *)  echo "Not an option, try again" ;;
        esac
    done
}

orch_usage() {
    sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'
    echo
    ccdc_usage_common | grep -v -- '--run\|--list'
    echo "  --from STEP        start at STEP (e.g. 01, 08_lateral_movement)"
    echo "  --only STEP[,..]   run only these steps (still in priority order)"
    echo "  --skip STEP[,..]   skip these steps"
    echo "  --list-steps       print the run order and exit"
}

orch_main() {
    local cfg="" a
    CCDC_SCRIPT_NAME=ccdc_orchestrator.sh
    while [ $# -gt 0 ]; do
        a=$1
        case $a in
            --auto|--non-interactive|-y) CCDC_NONINTERACTIVE=yes ;;
            --config) cfg=${2:-}; shift ;;
            --config=*) cfg=${a#*=} ;;
            --from) ORCH_FROM=$(resolve_step "${2:-}") || { echo "Unknown step: ${2:-}" >&2; exit 1; }; shift ;;
            --only) ORCH_ONLY=$(_resolve_csv "${2:-}") || exit 1; shift ;;
            --skip) ORCH_SKIP=$(_resolve_csv "${2:-}") || exit 1; shift ;;
            --list-steps) printf '%s.sh\n' "${CCDC_STEPS[@]}"; exit 0 ;;
            -h|--help) orch_usage; exit 0 ;;
            *) echo "Unknown option: $a (see --help)" >&2; exit 1 ;;
        esac
        shift
    done
    ccdc_init "$cfg" || exit 1
    if ccdc_noninteractive; then
        run_all
        exit $?
    fi
    orchestrator_menu
}

orch_main "$@"
