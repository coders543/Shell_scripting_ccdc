#!/usr/bin/env bash
# =====================================================================
#  common.sh - shared library for the CCDC Linux toolkit.
#  Sourced by every numbered script and the orchestrator. Not run directly.
# =====================================================================

[ -n "${BASH_VERSION:-}" ] || { echo "common.sh needs bash: sudo bash <script>.sh" >&2; return 1 2>/dev/null || exit 1; }
[ -n "${CCDC_COMMON_LOADED:-}" ] && return 0

if [ "${BASH_VERSINFO[0]}" -lt 4 ]; then
    echo "ERROR: bash 4.0+ required (this is bash $BASH_VERSION). Install a newer bash first." >&2
    return 1 2>/dev/null || exit 1
fi
CCDC_COMMON_LOADED=1
CCDC_VERSION="2.0.0"

# set -u only where empty-array expansion is safe (bash 4.4+)
if [ "${BASH_VERSINFO[0]}" -gt 4 ] || { [ "${BASH_VERSINFO[0]}" -eq 4 ] && [ "${BASH_VERSINFO[1]}" -ge 4 ]; }; then
    set -u
fi

CCDC_TOOLKIT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
CCDC_SCRIPT_NAME=${CCDC_SCRIPT_NAME:-$(basename "$0")}
CCDC_EXTRA_ARGS=()

have() { command -v "$1" >/dev/null 2>&1; }

# ---------------------------------------------------------------
# DISTRO / PACKAGE MANAGER / INIT SYSTEM DETECTION
# ---------------------------------------------------------------
PKG=""
if have apt-get; then PKG="apt"
elif have dnf; then PKG="dnf"
elif have yum; then PKG="yum"
elif have zypper; then PKG="zypper"
elif have pacman; then PKG="pacman"
elif have apk; then PKG="apk"
fi

opsys="unknown"
if [ -f /etc/os-release ]; then
    opsys=$(. /etc/os-release 2>/dev/null; echo "${ID:-unknown}")
fi

INIT_SYS="unknown"
if [ -d /run/systemd/system ] && have systemctl; then INIT_SYS="systemd"
elif have rc-service || have openrc; then INIT_SYS="openrc"
elif have service || [ -d /etc/init.d ]; then INIT_SYS="sysvinit"
fi

# ---------------------------------------------------------------
# PATHS (anchored to root's home so sudo/cron agree on location)
# ---------------------------------------------------------------
ccdc_set_paths() {
    local rh=""
    if have getent; then rh=$(getent passwd root 2>/dev/null | cut -d: -f6); fi
    [ -n "$rh" ] || rh=$(awk -F: '$1=="root"{print $6}' /etc/passwd 2>/dev/null)
    [ -n "$rh" ] || rh=/root
    CCDC_HOME=${CCDC_HOME:-$rh/ccdc}
    CCDC_BACKUPS=$CCDC_HOME/backups
    CCDC_LOGS=$CCDC_HOME/logs
    CCDC_INVENTORY=$CCDC_HOME/inventory
    CCDC_PCR=$CCDC_HOME/pcr
    CCDC_STAGING=$CCDC_HOME/staging
    CCDC_STATE=$CCDC_HOME/state
    CCDC_QUARANTINE=$CCDC_HOME/quarantine
    LOG=$CCDC_LOGS/script.log
}
CCDC_HOME_FROM_ENV=${CCDC_HOME:+1}
ccdc_set_paths

ccdc_ensure_dirs() {
    if [ ! -d "$CCDC_HOME" ]; then
        echo "NOTE: $CCDC_HOME does not exist yet (enumeration.sh not run on this box?) - creating it."
    fi
    mkdir -p "$CCDC_BACKUPS/pristine" "$CCDC_LOGS" "$CCDC_INVENTORY" "$CCDC_PCR" \
             "$CCDC_STAGING" "$CCDC_STATE" "$CCDC_QUARANTINE" || return 1
    chmod 700 "$CCDC_HOME" "$CCDC_BACKUPS" "$CCDC_PCR" "$CCDC_STAGING" "$CCDC_STATE" "$CCDC_QUARANTINE" 2>/dev/null
    return 0
}

# ---------------------------------------------------------------
# LOGGING / PROMPTS
# ---------------------------------------------------------------
log() {
    echo "$(date '+%F %T') [$CCDC_SCRIPT_NAME] -- $1" >> "$LOG" 2>/dev/null
    echo "$1"
}
warn() {
    echo "$(date '+%F %T') [$CCDC_SCRIPT_NAME] -- WARNING: $1" >> "$LOG" 2>/dev/null
    echo "WARNING: $1" >&2
}
err() {
    echo "$(date '+%F %T') [$CCDC_SCRIPT_NAME] -- ERROR: $1" >> "$LOG" 2>/dev/null
    echo "ERROR: $1" >&2
}

is_yes() {
    case "${1:-}" in
        [Yy]|[Yy][Ee][Ss]|[Tt][Rr][Uu][Ee]|1|[Oo][Nn]) return 0 ;;
    esac
    return 1
}

ccdc_noninteractive() { is_yes "${CCDC_NONINTERACTIVE:-no}"; }

pause() {
    ccdc_noninteractive && return 0
    read -r -p "Press [Enter] to continue..." _ || true
}

# ask "question" [CONFIG_VAR] [default-when-non-interactive]
ask() {
    local q=$1 var=${2:-} def=${3:-no} answer
    if ccdc_noninteractive; then
        answer=$def
        [ -n "$var" ] && answer=${!var:-$def}
        log "[auto] $q -> $answer${var:+ (from $var)}"
        is_yes "$answer"
        return
    fi
    read -r -p "$q (yes/no) " answer || { echo; return 1; }
    [ "$answer" = "yes" ] || [ "$answer" = "y" ]
}

# prompt_value "prompt" [CONFIG_VAR] [default]  -> value on stdout
prompt_value() {
    local q=$1 var=${2:-} def=${3:-} v=""
    if ccdc_noninteractive; then
        [ -n "$var" ] && v=${!var:-}
        echo "${v:-$def}"
        return
    fi
    read -r -p "$q " v || v=""
    echo "${v:-$def}"
}

# ---------------------------------------------------------------
# CONFIG (ccdc.conf: KEY=value lines, parsed - never sourced/eval'd)
# ---------------------------------------------------------------
CCDC_CONF_LOADED=""
ccdc_load_config() {
    local f=${1:-} c line key val
    if [ -z "$f" ]; then
        for c in "${CCDC_CONF:-}" "$PWD/ccdc.conf" "$CCDC_TOOLKIT_DIR/ccdc.conf" /etc/ccdc/ccdc.conf; do
            [ -n "$c" ] && [ -f "$c" ] && { f=$c; break; }
        done
    fi
    [ -n "$f" ] || return 0
    [ -f "$f" ] || { err "Config file not found: $f"; return 1; }
    while IFS= read -r line || [ -n "$line" ]; do
        line=${line%$'\r'}
        line="${line#"${line%%[![:space:]]*}"}"
        case $line in ''|'#'*) continue ;; esac
        if [[ $line =~ ^((CCDC|NEED)_[A-Z0-9_]+)=(.*)$ ]]; then
            key=${BASH_REMATCH[1]}; val=${BASH_REMATCH[3]}
        else
            warn "ccdc.conf: ignoring malformed line: $line"
            continue
        fi
        if [[ $val =~ ^\"(.*)\"$ ]] || [[ $val =~ ^\'(.*)\'$ ]]; then val=${BASH_REMATCH[1]}; fi
        # the PCR apply confirmation is a command-line flag only, never config
        [ "$key" = "CCDC_CONFIRM_PCR_SUBMITTED" ] && { warn "ccdc.conf: $key is ignored (CLI flag only)"; continue; }
        [ -n "${!key+x}" ] && continue
        printf -v "$key" '%s' "$val"
    done < "$f"
    CCDC_CONF_LOADED=$f
    return 0
}

# ---------------------------------------------------------------
# INIT / ENTRY POINT
# ---------------------------------------------------------------
require_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo "Run this as root (sudo bash $CCDC_SCRIPT_NAME)." >&2
        return 1
    fi
}

CCDC_INITIALIZED=0
ccdc_init() {
    [ "$CCDC_INITIALIZED" = 1 ] && return 0
    require_root || return 1
    [ -z "${CCDC_HOME_FROM_ENV:-}" ] && unset CCDC_HOME
    ccdc_load_config "${1:-}" || return 1
    ccdc_set_paths
    ccdc_ensure_dirs || { echo "Cannot create $CCDC_HOME" >&2; return 1; }
    local mode=interactive
    ccdc_noninteractive && mode=non-interactive
    echo "===== $(date '+%F %T') $CCDC_SCRIPT_NAME v$CCDC_VERSION started (pid $$, $mode, host $(hostname 2>/dev/null), $opsys/${PKG:-nopkg}/$INIT_SYS) =====" >> "$LOG"
    [ -n "$CCDC_CONF_LOADED" ] && log "Config loaded: $CCDC_CONF_LOADED"
    if ccdc_noninteractive && [ -z "$CCDC_CONF_LOADED" ]; then
        warn "Non-interactive mode with no ccdc.conf - environment variables and safe defaults only."
    fi
    [ -z "$PKG" ] && warn "No supported package manager found (apt/dnf/yum/zypper/pacman/apk) - install steps will be skipped."
    [ "$INIT_SYS" = "unknown" ] && warn "No supported service manager found (systemd/OpenRC/sysvinit) - service restarts will be skipped."
    CCDC_INITIALIZED=1
}

ccdc_usage_common() {
    cat <<EOF
Common options:
  --auto, --non-interactive, -y   no prompts; answers come from ccdc.conf / env vars, safe defaults otherwise
  --config FILE                   load answers from FILE (default search: \$CCDC_CONF, ./ccdc.conf,
                                  <toolkit dir>/ccdc.conf, /etc/ccdc/ccdc.conf)
  --run ACTION                    run a single action and exit (see --list)
  --list                          list actions this script supports
  -h, --help                      this help
EOF
}

# ccdc_main PREFIX "$@"  - each script defines PREFIX_menu, PREFIX_auto, PREFIX_run_action, PREFIX_actions
ccdc_main() {
    local prefix=$1 cfg="" list=0
    shift
    CCDC_SCRIPT_NAME=$(basename "$0")
    while [ $# -gt 0 ]; do
        case $1 in
            --auto|--non-interactive|-y) CCDC_NONINTERACTIVE=yes ;;
            --config) cfg=${2:-}; shift ;;
            --config=*) cfg=${1#*=} ;;
            --run) CCDC_RUN_ACTION=${2:-}; shift ;;
            --run=*) CCDC_RUN_ACTION=${1#*=} ;;
            --list) list=1 ;;
            -h|--help) echo "Usage: sudo bash $CCDC_SCRIPT_NAME [options]"; ccdc_usage_common
                       echo; echo "Actions:"; "${prefix}_actions"; exit 0 ;;
            *) CCDC_EXTRA_ARGS+=("$1") ;;
        esac
        shift
    done
    if [ "$list" = 1 ]; then "${prefix}_actions"; exit 0; fi
    ccdc_init "$cfg" || exit 1
    if [ -n "${CCDC_RUN_ACTION:-}" ]; then
        "${prefix}_run_action" "$CCDC_RUN_ACTION"
        exit $?
    elif ccdc_noninteractive; then
        "${prefix}_auto"
        exit $?
    else
        "${prefix}_menu"
    fi
}

has_extra_arg() {
    local a
    for a in ${CCDC_EXTRA_ARGS[@]+"${CCDC_EXTRA_ARGS[@]}"}; do [ "$a" = "$1" ] && return 0; done
    return 1
}

# ccdc_menu "Title" "label" func "label" func ...
ccdc_menu() {
    local title=$1 choice i
    shift
    local -a labels=() funcs=()
    while [ $# -ge 2 ]; do labels+=("$1"); funcs+=("$2"); shift 2; done
    while true; do
        echo "============================================================"
        echo " $title"
        echo " host: $(hostname 2>/dev/null) | $opsys | pkg: ${PKG:-none} | init: $INIT_SYS"
        echo "============================================================"
        for i in "${!labels[@]}"; do printf ' %2d) %s\n' $((i + 1)) "${labels[$i]}"; done
        echo "  q) Quit"
        read -r -p "Pick an option: " choice || { echo; return 0; }
        case $choice in q|Q|quit|exit) return 0 ;; esac
        if [[ $choice =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le ${#labels[@]} ]; then
            ${funcs[$((choice - 1))]}
            pause
        else
            echo "Not an option, try again"
        fi
    done
}

# ---------------------------------------------------------------
# PACKAGE WRAPPERS
# ---------------------------------------------------------------
pkg_install() {
    case $PKG in
        apt)     DEBIAN_FRONTEND=noninteractive apt-get install -y "$@" \
                     || { apt-get update -y >/dev/null 2>&1 && DEBIAN_FRONTEND=noninteractive apt-get install -y "$@"; } ;;
        dnf)     dnf install -y "$@" ;;
        yum)     yum install -y "$@" ;;
        zypper)  zypper --non-interactive install "$@" ;;
        pacman)  pacman -S --noconfirm "$@" ;;
        apk)     apk add --no-cache "$@" ;;
        *)       echo "No known package manager found, install manually: $*"; return 1 ;;
    esac
}

pkg_remove() {
    case $PKG in
        apt)     DEBIAN_FRONTEND=noninteractive apt-get purge -y "$@" ;;
        dnf)     dnf remove -y "$@" ;;
        yum)     yum remove -y "$@" ;;
        zypper)  zypper --non-interactive remove "$@" ;;
        pacman)  pacman -Rns --noconfirm "$@" ;;
        apk)     apk del "$@" ;;
        *)       echo "No known package manager found, remove manually: $*"; return 1 ;;
    esac
}

pkg_update_all() {
    case $PKG in
        apt)     apt-get update -y && DEBIAN_FRONTEND=noninteractive apt-get upgrade -y ;;
        dnf)     dnf upgrade -y ;;
        yum)     yum update -y ;;
        zypper)  zypper --non-interactive update ;;
        pacman)  pacman -Syu --noconfirm ;;
        apk)     apk update && apk upgrade ;;
        *)       echo "No known package manager found, update manually"; return 1 ;;
    esac
}

pkg_is_installed() {
    local p=$1
    if have dpkg; then dpkg -s "$p" >/dev/null 2>&1 && return 0; fi
    if have rpm; then rpm -q "$p" >/dev/null 2>&1 && return 0; fi
    if have pacman; then pacman -Q "$p" >/dev/null 2>&1 && return 0; fi
    if have apk; then apk info -e "$p" >/dev/null 2>&1 && return 0; fi
    return 1
}

# ---------------------------------------------------------------
# SERVICE HELPERS (systemd / OpenRC / sysvinit)
# ---------------------------------------------------------------
svc_exists() {
    local n=$1
    case $INIT_SYS in
        systemd) systemctl list-unit-files --type=service 2>/dev/null | grep -q "^${n}\.service" ;;
        openrc)  [ -x "/etc/init.d/$n" ] ;;
        sysvinit) [ -x "/etc/init.d/$n" ] ;;
        *) return 1 ;;
    esac
}

svc_is_active() {
    local n=$1
    case $INIT_SYS in
        systemd) systemctl is-active --quiet "$n" ;;
        openrc)  rc-service "$n" status >/dev/null 2>&1 ;;
        sysvinit) service "$n" status >/dev/null 2>&1 ;;
        *) return 1 ;;
    esac
}

svc_stop_disable() {
    local n=$1
    case $INIT_SYS in
        systemd) systemctl stop "$n" 2>/dev/null; systemctl disable "$n" 2>/dev/null ;;
        openrc)  rc-service "$n" stop 2>/dev/null; rc-update del "$n" 2>/dev/null ;;
        sysvinit) service "$n" stop 2>/dev/null
                  if have update-rc.d; then update-rc.d "$n" disable 2>/dev/null
                  elif have chkconfig; then chkconfig "$n" off 2>/dev/null; fi ;;
        *) return 1 ;;
    esac
}

svc_enable_now() {
    local n=$1
    case $INIT_SYS in
        systemd) systemctl enable --now "$n" 2>/dev/null ;;
        openrc)  rc-update add "$n" default 2>/dev/null; rc-service "$n" start 2>/dev/null ;;
        sysvinit) service "$n" start 2>/dev/null
                  if have update-rc.d; then update-rc.d "$n" enable 2>/dev/null
                  elif have chkconfig; then chkconfig "$n" on 2>/dev/null; fi ;;
        *) return 1 ;;
    esac
}

# restart_service name1 [name2 ...] - restarts the first one that exists
restart_service() {
    local name
    for name in "$@"; do
        if svc_exists "$name"; then
            case $INIT_SYS in
                systemd) systemctl restart "$name" 2>/dev/null && { log "Restarted $name"; return 0; } ;;
                openrc)  rc-service "$name" restart >/dev/null 2>&1 && { log "Restarted $name"; return 0; } ;;
                sysvinit) service "$name" restart >/dev/null 2>&1 && { log "Restarted $name"; return 0; } ;;
            esac
            warn "Restart of $name FAILED - check it now, it may be a scored service"
            return 1
        fi
    done
    return 1
}

# ---------------------------------------------------------------
# FILE HELPERS
# ---------------------------------------------------------------
# backup_file FILE... - keeps a never-overwritten pristine copy plus a timestamped copy
backup_file() {
    local f safe
    for f in "$@"; do
        [ -e "$f" ] || continue
        safe=$(printf '%s' "$f" | sed 's#^/##; s#/#__#g')
        [ -e "$CCDC_BACKUPS/pristine/$safe" ] || cp -a "$f" "$CCDC_BACKUPS/pristine/$safe" 2>/dev/null
        cp -a "$f" "$CCDC_BACKUPS/$safe.$(date +%Y%m%d_%H%M%S)" 2>/dev/null
    done
}

_re_escape()  { printf '%s' "$1" | sed 's/[][\.*^$/+?(){}|]/\\&/g'; }
_sed_repl()   { printf '%s' "$1" | sed 's/[&/\]/\\&/g'; }

# set_line FILE KEY SEP VALUE  -- replace a (possibly commented) key, or append it
set_line() {
    local file=$1 key=$2 sep=$3 value=$4 kre
    [ -f "$file" ] || touch "$file"
    kre=$(_re_escape "$key")
    if grep -Eq "^[#;]*[[:space:]]*${kre}([[:space:]]|=|$)" "$file" 2>/dev/null; then
        sed -i -E "s/^[#;]*[[:space:]]*${kre}([[:space:]]|=|$).*/$(_sed_repl "$key$sep$value")/" "$file"
    else
        echo "$key$sep$value" >> "$file"
    fi
}

# ---------------------------------------------------------------
# SSHD HELPERS (Match-block and sshd_config.d aware, validated)
# ---------------------------------------------------------------
SSHD_CONF=/etc/ssh/sshd_config
SSHD_DROPIN=/etc/ssh/sshd_config.d/00-ccdc-hardening.conf

sshd_bin() {
    local b
    b=$(command -v sshd 2>/dev/null) && { echo "$b"; return 0; }
    for b in /usr/sbin/sshd /usr/local/sbin/sshd /sbin/sshd; do [ -x "$b" ] && { echo "$b"; return 0; }; done
    return 1
}

sshd_uses_dropins() {
    [ -d /etc/ssh/sshd_config.d ] && grep -Eiq '^[[:space:]]*Include[[:space:]]+.*sshd_config\.d' "$SSHD_CONF" 2>/dev/null
}

# _sshd_set_in FILE KEY VALUE - first occurrence (commented or not) outside Match blocks wins
_sshd_set_in() {
    local file=$1 key=$2 val=$3 tmp
    [ -f "$file" ] || touch "$file"
    tmp=$(mktemp "$CCDC_STATE/sshd.XXXXXX") || return 1
    awk -v k="$key" -v v="$val" '
        BEGIN { lk = tolower(k); done = 0; inmatch = 0 }
        {
            t = $0; sub(/^[# \t]*/, "", t); n = split(t, a, /[ \t=]+/); w = tolower(a[1])
            if (!inmatch && w == "match" && substr($0, 1, 1) != "#") {
                if (!done) { print k " " v; done = 1 }
                inmatch = 1; print; next
            }
            if (!inmatch && w == lk) {
                if (!done) { print k " " v; done = 1; next }
                if (substr($0, 1, 1) != "#") next
            }
            print
        }
        END { if (!done) print k " " v }' "$file" > "$tmp" && cat "$tmp" > "$file"
    rm -f "$tmp"
}

sshd_begin_change() {
    SSHD_SNAP=$(mktemp -d "$CCDC_STATE/sshd_snap.XXXXXX") || return 1
    cp -a "$SSHD_CONF" "$SSHD_SNAP/sshd_config" 2>/dev/null
    [ -f "$SSHD_DROPIN" ] && cp -a "$SSHD_DROPIN" "$SSHD_SNAP/dropin"
    backup_file "$SSHD_CONF" "$SSHD_DROPIN"
}

sshd_set() {
    _sshd_set_in "$SSHD_CONF" "$1" "$2"
    if sshd_uses_dropins; then _sshd_set_in "$SSHD_DROPIN" "$1" "$2"; chmod 600 "$SSHD_DROPIN"; fi
}

# validate with sshd -t; restart on success, roll back on failure
sshd_commit_change() {
    local b out
    if b=$(sshd_bin); then
        if ! out=$("$b" -t 2>&1); then
            err "sshd -t rejected the new config - ROLLING BACK. sshd said: $out"
            cp -a "$SSHD_SNAP/sshd_config" "$SSHD_CONF"
            if [ -f "$SSHD_SNAP/dropin" ]; then cp -a "$SSHD_SNAP/dropin" "$SSHD_DROPIN"; else rm -f "$SSHD_DROPIN"; fi
            rm -rf "$SSHD_SNAP"
            return 1
        fi
    else
        warn "sshd binary not found; cannot validate config before restart"
    fi
    rm -rf "$SSHD_SNAP"
    restart_service ssh sshd || { [ "$INIT_SYS" = sysvinit ] && service sshd restart >/dev/null 2>&1; }
    echo ">>> Test a NEW ssh login in a second terminal before closing this one. <<<"
    return 0
}

# ---------------------------------------------------------------
# USERS / README ANSWERS
# ---------------------------------------------------------------
authorized=()
admins=()
CCDC_USERS_LOADED=0

normal_users() {
    awk -F: '($3 >= 1000 && $3 < 60000) || ($3 >= 500 && $3 < 1000 && $7 !~ /nologin|false/) {print $1}' /etc/passwd
}

_read_list_file() {
    sed -e 's/\r$//' -e 's/#.*//' -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' "$1" | grep -v '^$'
}

# fills authorized[] (users + admins) and admins[]; returns 1 if no list could be obtained
load_users() {
    [ "$CCDC_USERS_LOADED" = 1 ] && return 0
    local uf="" af="" d
    if [ -n "${CCDC_USERS_FILE:-}" ] && [ -n "${CCDC_ADMINS_FILE:-}" ]; then
        uf=$CCDC_USERS_FILE; af=$CCDC_ADMINS_FILE
    else
        for d in "$PWD" "$CCDC_TOOLKIT_DIR"; do
            if [ -f "$d/users.txt" ] && [ -f "$d/admin.txt" ]; then uf=$d/users.txt; af=$d/admin.txt; break; fi
        done
    fi
    if [ -n "$uf" ] && [ -f "$uf" ] && [ -f "$af" ]; then
        mapfile -t authorized < <(_read_list_file "$uf")
        mapfile -t admins < <(_read_list_file "$af")
        echo "Loaded $uf and $af"
    elif [ -n "${CCDC_AUTHORIZED_USERS:-}${CCDC_ADMINS:-}" ]; then
        read -r -a authorized <<< "${CCDC_AUTHORIZED_USERS:-}"
        read -r -a admins <<< "${CCDC_ADMINS:-}"
        echo "Loaded user lists from CCDC_AUTHORIZED_USERS / CCDC_ADMINS"
    elif ccdc_noninteractive; then
        err "No authorized user list (users.txt+admin.txt, CCDC_USERS_FILE/CCDC_ADMINS_FILE, or CCDC_AUTHORIZED_USERS/CCDC_ADMINS)."
        return 1
    else
        echo "Type all AUTHORIZED users (space separated):"
        read -r -a authorized || true
        echo "Type the ADMINS (space separated):"
        read -r -a admins || true
    fi
    authorized=(${authorized[@]+"${authorized[@]}"} ${admins[@]+"${admins[@]}"})
    if [ ${#authorized[@]} -eq 0 ]; then
        err "Authorized user list is empty - refusing to treat every account as unauthorized."
        return 1
    fi
    CCDC_USERS_LOADED=1
    log "Authorized users: ${authorized[*]} | admins: ${admins[*]:-none}"
}

# lock, never delete - expiry also blocks SSH-key logins
lock_account() {
    local u=$1
    if have usermod; then
        usermod -L -e 1 "$u" 2>/dev/null || usermod -L "$u" 2>/dev/null
    else
        passwd -l "$u" >/dev/null 2>&1
    fi
    log "$u locked (not deleted). Undo: usermod -U -e '' $u  (or: passwd -u $u)"
}

in_list() {
    local x=$1 y
    shift
    for y in "$@"; do [ "$x" = "$y" ] && return 0; done
    return 1
}

is_authorized() { in_list "$1" ${authorized[@]+"${authorized[@]}"}; }
is_admin()      { in_list "$1" ${admins[@]+"${admins[@]}"}; }

declare -A need
CCDC_README_SERVICES=(ssh ftp web mysql postgres php samba dns mail)
CCDC_README_DONE=0

readme_summary() {
    local s out=""
    for s in "${CCDC_README_SERVICES[@]}"; do out+="$s=${need[$s]:-?} "; done
    echo "$out"
}

# README service -> candidate unit names (first existing one is used)
declare -A CCDC_SVC_UNITS=(
    [ssh]="ssh sshd"
    [ftp]="vsftpd proftpd pure-ftpd"
    [web]="apache2 httpd nginx lighttpd"
    [mysql]="mysql mysqld mariadb"
    [postgres]="postgresql"
    [php]="php-fpm php8.3-fpm php8.2-fpm php8.1-fpm php7.4-fpm"
    [samba]="smbd nmbd smb nmb samba"
    [dns]="named bind9"
    [mail]="postfix exim4 exim sendmail dovecot"
)

# load saved README answers into need[] without prompting (read-only consumers)
readme_load_saved() {
    [ "$CCDC_README_DONE" = 1 ] && return 0
    local f=$CCDC_STATE/readme_services.conf k v
    [ -f "$f" ] || return 1
    while IFS='=' read -r k v; do [[ $k =~ ^[a-z]+$ ]] && need[$k]=$v; done < "$f"
    return 0
}

# README "does this box need X" answers: config NEED_* -> saved state -> prompt
readme_services() {
    [ "$CCDC_README_DONE" = 1 ] && return 0
    local svc var any=0 missing=0 statef=$CCDC_STATE/readme_services.conf k v
    for svc in "${CCDC_README_SERVICES[@]}"; do
        var="NEED_${svc^^}"
        if [ -n "${!var:-}" ]; then
            any=1
            if is_yes "${!var}"; then need[$svc]=yes; else need[$svc]=no; fi
        else
            missing=1
        fi
    done
    if [ "$missing" = 1 ] && [ -f "$statef" ]; then
        local -A saved=()
        while IFS='=' read -r k v; do
            [[ $k =~ ^[a-z]+$ ]] && saved[$k]=$v
        done < "$statef"
        local preview=""
        for svc in "${CCDC_README_SERVICES[@]}"; do preview+="$svc=${need[$svc]:-${saved[$svc]:-?}} "; done
        if ccdc_noninteractive || ask "Reuse saved README answers ($preview)?"; then
            for svc in "${CCDC_README_SERVICES[@]}"; do
                [ -n "${need[$svc]:-}" ] || need[$svc]=${saved[$svc]:-no}
            done
            missing=0
        fi
    fi
    if [ "$missing" = 1 ]; then
        if ccdc_noninteractive; then
            if [ "$any" = 0 ]; then
                err "No README service answers (set NEED_SSH=yes/no etc. in ccdc.conf)."
                return 1
            fi
            for svc in "${CCDC_README_SERVICES[@]}"; do [ -n "${need[$svc]:-}" ] || need[$svc]=no; done
        else
            for svc in "${CCDC_README_SERVICES[@]}"; do
                [ -n "${need[$svc]:-}" ] && continue
                if ask "Does the README/inject say this box needs: $svc?"; then need[$svc]=yes; else need[$svc]=no; fi
            done
        fi
    fi
    : > "$statef"
    for svc in "${CCDC_README_SERVICES[@]}"; do
        echo "$svc=${need[$svc]}" >> "$statef"
        log "README: need $svc = ${need[$svc]}"
    done
    CCDC_README_DONE=1
}

# ---------------------------------------------------------------
# NETWORK HELPERS
# ---------------------------------------------------------------
list_listening() {
    if have ss; then ss -tulnp 2>/dev/null
    elif have netstat; then netstat -tulnp 2>/dev/null
    else echo "(neither ss nor netstat available)"; return 1
    fi
}

listening_ports() {
    { if have ss; then ss -tuln 2>/dev/null; else netstat -tuln 2>/dev/null; fi; } \
        | awk 'NR>1 {print $5}' | grep -oE '[0-9]+$' | sort -un
}

# firewall backend, in required fallback order; CCDC_FW_BACKEND overrides
fw_detect_backend() {
    if [ -n "${CCDC_FW_BACKEND:-}" ]; then echo "$CCDC_FW_BACKEND"; return; fi
    if have nft; then echo nft
    elif have ufw; then echo ufw
    elif have firewall-cmd; then echo firewalld
    elif have iptables; then echo iptables
    else echo none
    fi
}

# stable text fingerprint of the CCDC-managed rules; the watchdog compares cksums of this
fw_signature() {
    case $1 in
        nft)       nft list table inet ccdc 2>/dev/null; nft list table inet ccdc_egress 2>/dev/null ;;
        iptables)  iptables -S INPUT 2>/dev/null; iptables -S OUTPUT 2>/dev/null; iptables -S FORWARD 2>/dev/null | head -n 1
                   if command -v ip6tables >/dev/null 2>&1; then ip6tables -S INPUT 2>/dev/null; ip6tables -S OUTPUT 2>/dev/null; fi ;;
        ufw)       ufw status verbose 2>/dev/null ;;
        firewalld) firewall-cmd --get-default-zone 2>/dev/null; firewall-cmd --zone=drop --list-all 2>/dev/null
                   firewall-cmd --direct --get-all-rules 2>/dev/null ;;
    esac
}

# ---------------------------------------------------------------
# PORT WATCHLISTS (single shared definition)
# port -> "Name|Risk note"
# ---------------------------------------------------------------
declare -A PORT_WATCHLIST=(
    [21]="FTP|Unencrypted, prone to anonymous access/brute force. Prefer SFTP (22)."
    [22]="SSH|Red team will brute-force or look for default/compromised keys."
    [23]="Telnet|Unencrypted credentials. Disable immediately."
    [53]="DNS|Critical for AD, but also abused for C2/exfil via DNS tunneling."
    [80]="HTTP|Watch for dropped web shells. Should redirect to 443."
    [88]="Kerberos|Watch for abnormal TGT requests / Kerberoasting / ticket tampering."
    [135]="MS-RPC/Epmap|Used for remote admin and system enumeration."
    [137]="NetBIOS|Legacy Windows naming service, enables enumeration."
    [138]="NetBIOS|Legacy Windows datagram service, enables enumeration."
    [139]="NetBIOS|Legacy Windows session service, enables enumeration."
    [389]="LDAP|Unencrypted AD queries/credential sniffing. Force LDAPS (636)."
    [443]="HTTPS|Confirm cert is valid and traffic is actually encrypted."
    [445]="SMB|High-risk lateral movement/exploit vector (e.g. EternalBlue). Disable SMBv1."
    [636]="LDAPS|Encrypted AD queries - this is the one 389 should be forced to."
    [1433]="MSSQL|Database port, should never face the open network."
    [3306]="MySQL|Database port, should never face the open network."
    [3389]="RDP|Frequently targeted for brute force and ransomware deployment."
    [5432]="PostgreSQL|Database port, should never face the open network."
    [5985]="WinRM HTTP|Used for lateral movement across Windows hosts."
    [5986]="WinRM HTTPS|Used for lateral movement across Windows hosts."
)

# hunting list only - default-deny already blocks these; port -> "Name|Category|Note"
declare -A MALWARE_PORT_WATCHLIST=(
    [69]="TFTP|Legacy Protocol|No auth at all, used for malware staging/pulling payloads."
    [1337]="Elite/Leet|Malware|Classic backdoor/CTF convention port, rarely legitimate."
    [2222]="SSH-alt/DoHC2|C2|Legit alt-SSH, but also used by DoHC2/externalc2/Qakbot traffic."
    [3000]="BeEF/ptunnel-ng|C2|BeEF Browser Exploitation Framework default panel."
    [3030]="Nuages C2|C2|Default port for the Nuages C2 framework."
    [3389]="RDP|Lateral Movement|Already on the main watchlist - also watch for *outbound* RDP (rogue/malRDP)."
    [4444]="Metasploit/Meterpreter|C2|THE classic default reverse-shell listener port."
    [5900]="VNC|RMM|VNC default port range (5900-5910), unauthenticated remote desktop risk."
    [5938]="TeamViewer|RMM|Legit tool, but unexpected use is a lateral-movement/persistence red flag."
    [6379]="Redis|Database|Frequently left completely unauthenticated by default."
    [6568]="AnyDesk|RMM|Legit tool, same logic as TeamViewer above."
    [6666]="Kali default/IRC botnet|Malware|Kali's default port, also CVE-2024-38112/Void Banshee abuse."
    [6667]="IRC|Malware|Classic IRC-based botnet C2 channel."
    [7681]="Supershell C2|C2|Supershell C2 framework default port."
    [7777]="Port Inspector/misc C2|C2|Low-confidence but worth a glance if seen listening."
    [8888]="POSHC2|C2|POSHC2 framework default port (also legitimate uses exist)."
    [9001]="Tor relay|Defense Evasion|Default Tor ORPort - Tor traffic off a scored box is a red flag."
    [9050]="Tor SOCKS proxy|Defense Evasion|Default Tor SOCKS proxy port."
    [9051]="Tor controller|Defense Evasion|Default Tor control port."
    [12345]="NetBus|Malware|Classic 90s trojan, still used as a CCDC-injected joke/backdoor."
    [12346]="NetBus|Malware|Same family as 12345."
    [21115]="RustDesk|RMM|Legit tool, unexpected use is a lateral-movement red flag."
    [21116]="RustDesk|RMM|Same family as 21115."
    [22000]="ShadowPad|Malware (nation-state)|Chinese-attributed espionage backdoor default port (also some legit uses)."
    [22001]="ShadowPad|Malware (nation-state)|Same family as 22000."
    [31337]="Back Orifice/SliverC2|C2|The classic 'elite' port - Back Orifice, SliverC2, and ThunderShell all default here."
    [50050]="Cobalt Strike clone/SharpC2|C2|Common default for SharpC2 and similar Cobalt Strike-alikes."
    [53531]="dnscat2|C2|dnscat2 default port - DNS-tunneled C2."
    [55553]="Metasploit RPC/Armitage|C2|msfrpcd and Armitage team server default port."
    [8936]="MoonPeak|Malware (nation-state)|North Korean (UAT-5394) malware family default port."
)
