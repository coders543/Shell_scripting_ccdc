#!/usr/bin/env bash
# =====================================================================
#  99_optional_media_games.sh - OPTIONAL CyberPatriot-style prohibited
#  media / games sweep. Not attack-tactic mapped. NEVER run by the
#  orchestrator's default or non-interactive path - invoke it by name.
#  Always scans first; nothing moves or is deleted without a typed "yes".
#  --auto = scan + report only (never deletes, never quarantines).
# =====================================================================
[ -n "${BASH_VERSION:-}" ] || { echo "Run with bash: sudo bash $0" >&2; exit 1; }
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh" || { echo "common.sh missing next to $0" >&2; exit 1; }

MEDIA_EXTENSIONS=(mp3 mp4 avi mov mkv wav ogg flac wmv m4a mpeg mpg)
OTHER_EXTENSIONS=(jpg jpeg png gif tif tiff zip tar)
MEDIA_LIST=""

media_scan() {
    echo "This is an OPTIONAL extension - most CCDC rubrics don't score this."
    echo "It only scans and reports by default. Deletion is a separate confirm."
    local ts report ext pattern
    ts=$(date +%Y%m%d_%H%M%S)
    report=$CCDC_INVENTORY/media_games_sweep_$ts.txt
    MEDIA_LIST=$CCDC_STATE/media_files_$ts.lst
    : > "$MEDIA_LIST"
    for ext in "${MEDIA_EXTENSIONS[@]}"; do
        find / -xdev -type f -iname "*.$ext" ! -path "$CCDC_HOME/*" 2>/dev/null >> "$MEDIA_LIST"
    done

    {
        echo "=== Audio/video files (whole filesystem) ==="
        cat "$MEDIA_LIST"

        echo; echo "=== Pictures/archives in /home (not deleted, just listed) ==="
        for ext in "${OTHER_EXTENSIONS[@]}"; do
            find /home -type f -iname "*.$ext" 2>/dev/null
        done

        echo; echo "=== Suspicious filenames (review by hand, not auto-deleted) ==="
        for pattern in "*backdoor*" "*.php" "*.tar.gz" "*keylog*" "*exploit*"; do
            find / -xdev -type f -iname "$pattern" ! -path "$CCDC_HOME/*" 2>/dev/null
        done

        echo; echo "=== Packages that look like games ==="
        case $PKG in
            apt) dpkg -l | grep -i game ;;
            dnf|yum|zypper) rpm -qa | grep -i game ;;
            pacman) pacman -Qq | grep -i game ;;
            apk) apk info | grep -i game ;;
        esac
    } > "$report"

    echo "Sweep complete, results: $report ($(wc -l < "$MEDIA_LIST") audio/video files)"
    echo "READ THIS FILE before deleting anything - some media may be needed for an inject."
    log "Media/games sweep written to $report"
}

media_remove() {
    [ -n "$MEDIA_LIST" ] && [ -f "$MEDIA_LIST" ] || media_scan
    [ -s "$MEDIA_LIST" ] || { echo "No audio/video files found."; return 0; }
    if ccdc_noninteractive; then
        echo "Non-interactive mode: scan only. Re-run interactively to quarantine/delete."
        return 0
    fi
    local f dest qdir
    if ask "Quarantine (move) the $(wc -l < "$MEDIA_LIST") audio/video files to $CCDC_QUARANTINE/media? (reversible)"; then
        qdir=$CCDC_QUARANTINE/media
        while IFS= read -r f; do
            [ -f "$f" ] || continue
            dest=$qdir$f
            mkdir -p "$(dirname "$dest")" && mv "$f" "$dest" && echo "moved: $f"
        done < "$MEDIA_LIST"
        log "Audio/video files quarantined to $qdir (extension task, confirmed)"
    elif ask "Delete all found audio/video files now? (irreversible)"; then
        while IFS= read -r f; do
            [ -f "$f" ] && rm -f "$f" && echo "deleted: $f"
        done < "$MEDIA_LIST"
        log "Audio/video files deleted (extension task, confirmed)"
    else
        echo "Nothing moved or deleted. Review the report and re-run if you want to."
    fi
}

extension_media_and_games() {
    media_scan
    media_remove
}

media_games_auto() { media_scan; return 0; }

media_games_actions() {
    cat <<'EOF'
  auto     scan + report only
  scan     scan + report only
  sweep    scan, then (interactive) quarantine or delete audio/video files
EOF
}

media_games_run_action() {
    case $1 in
        auto|scan) media_scan ;;
        sweep) extension_media_and_games ;;
        *) err "Unknown action: $1"; media_games_actions; return 2 ;;
    esac
}

media_games_menu() {
    ccdc_menu "99_optional_media_games.sh - OPTIONAL prohibited media/games sweep" \
        "Scan + report (no changes)" media_scan \
        "Scan, then quarantine/delete audio/video (confirm)" extension_media_and_games
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    ccdc_main media_games "$@"
fi
