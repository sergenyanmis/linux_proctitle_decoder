#!/usr/bin/env bash
set -u

# -----------------------------------------------------------------------------
# auditd-proctitle-decoder
#
# Decodes the hexadecimal "proctitle=" field from Linux auditd PROCTITLE events,
# appends a human-readable "decoded_proctitle=" field, and forwards the enriched
# event to a remote SIEM/syslog receiver over UDP.
#
# Configuration can be supplied with environment variables:
#
#   SIEM_HOST        Destination hostname/IP        (default: 127.0.0.1)
#   SIEM_PORT        Destination UDP port           (default: 514)
#   DEFAULT_PRI      Syslog PRI if one is missing   (default: <182>)
#   DEBUG            1 enables debug logging        (default: 0)
#   DEBUG_FILE       Debug log path                 (default: /var/log/decode_proctitle.debug)
#
# Example:
#   SIEM_HOST=192.0.2.10 SIEM_PORT=514 /usr/local/bin/decode.sh
# -----------------------------------------------------------------------------

SIEM_HOST="${SIEM_HOST:-127.0.0.1}"
SIEM_PORT="${SIEM_PORT:-514}"
DEFAULT_PRI="${DEFAULT_PRI:-<182>}"

DEBUG="${DEBUG:-0}"
DEBUG_FILE="${DEBUG_FILE:-/var/log/decode_proctitle.debug}"

send_udp() {
    local msg="$1"

    # /dev/udp is a Bash feature.
    (
        printf '%s' "$msg" >"/dev/udp/${SIEM_HOST}/${SIEM_PORT}"
    ) 2>/dev/null || true
}

dbg() {
    [[ "$DEBUG" == "1" ]] || return 0

    (
        printf '%s\n' "$1" >> "$DEBUG_FILE"
    ) 2>/dev/null || (
        printf '%s\n' "$1" >> /tmp/decode_proctitle.debug 2>/dev/null || true
    )
}

hex_to_ascii() {
    local hex="$1"
    local out=""
    local i=0
    local len=${#hex}

    # Ignore a trailing half-byte if malformed input is received.
    (( len % 2 == 1 )) && len=$((len - 1))

    while (( i < len )); do
        local byte="${hex:i:2}"

        # auditd PROCTITLE separates argv entries with NULL bytes.
        if [[ "$byte" == "00" ]]; then
            out+=" "
        else
            local ch=""

            printf -v ch "\\x${byte}" 2>/dev/null || ch=" "

            case "$ch" in
                $'\t'|$'\r'|$'\n')
                    ch=" "
                    ;;
            esac

            [[ "$ch" == [[:print:]] ]] || ch=" "
            out+="$ch"
        fi

        (( i += 2 ))
    done

    # Collapse repeated whitespace without invoking external commands.
    local compact=""
    local prev_space=0
    local j=0
    local olen=${#out}

    while (( j < olen )); do
        local c="${out:j:1}"

        if [[ "$c" == " " ]]; then
            if (( prev_space == 0 )); then
                compact+=" "
                prev_space=1
            fi
        else
            compact+="$c"
            prev_space=0
        fi

        (( j += 1 ))
    done

    # Trim one possible leading/trailing space.
    compact="${compact# }"
    compact="${compact% }"

    printf '%s' "$compact"
}

escape_field_value() {
    local value="$1"

    # Keep decoded_proctitle="..." parseable if the command itself contains
    # backslashes or quotation marks.
    value="${value//\\/\\\\}"
    value="${value//\"/\\\"}"

    printf '%s' "$value"
}

iso_to_syslog_ts() {
    local ymd="$1"
    local hms="$2"
    local mm="${ymd:5:2}"
    local dd="${ymd:8:2}"
    local mon

    case "$mm" in
        01) mon="Jan" ;;
        02) mon="Feb" ;;
        03) mon="Mar" ;;
        04) mon="Apr" ;;
        05) mon="May" ;;
        06) mon="Jun" ;;
        07) mon="Jul" ;;
        08) mon="Aug" ;;
        09) mon="Sep" ;;
        10) mon="Oct" ;;
        11) mon="Nov" ;;
        12) mon="Dec" ;;
        *)  mon="Jan" ;;
    esac

    printf '%s %s %s' "$mon" "$dd" "$hms"
}

while IFS= read -r line; do
    dbg "IN: $line"

    # Avoid loops if an enriched event is accidentally fed back to this script.
    [[ "$line" == *"decoded_proctitle="* ]] && {
        dbg "SKIP: already decoded"
        continue
    }

    # Accept common separators after type=PROCTITLE, such as whitespace,
    # colon or comma.
    [[ "$line" =~ type=PROCTITLE([^A-Za-z0-9]|$) ]] || continue

    # proctitle is expected to contain hexadecimal bytes.
    [[ "$line" =~ proctitle=([0-9A-Fa-f]+) ]] || {
        dbg "SKIP: no proctitle hex"
        continue
    }

    HEX_CMD="${BASH_REMATCH[1]}"
    DECODED="$(hex_to_ascii "$HEX_CMD")"

    [[ -n "${DECODED// }" ]] || DECODED="(decode_failed)"
    DECODED_ESCAPED="$(escape_field_value "$DECODED")"

    # Extract PRI cleanly if present.
    pri="$DEFAULT_PRI"
    rest="$line"

    if [[ "$rest" =~ ^(\<[0-9]+\>)[[:space:]]*(.*)$ ]]; then
        pri="${BASH_REMATCH[1]}"
        rest="${BASH_REMATCH[2]}"
    fi

    # Convert an RFC3339/ISO-style rsyslog timestamp to traditional syslog
    # timestamp format when the input matches the expected pattern.
    #
    # Example:
    # 2026-08-20T22:10:11.123456+03:00 host ...
    # becomes:
    # Aug 20 22:10:11 host ...
    if [[ "$rest" =~ ^([0-9]{4}-[0-9]{2}-[0-9]{2})T([0-9]{2}:[0-9]{2}:[0-9]{2})(\.[0-9]+)?([+-][0-9]{2}:[0-9]{2}|Z)[[:space:]]+([^[:space:]]+)[[:space:]]+(.*)$ ]]; then
        ymd="${BASH_REMATCH[1]}"
        hms="${BASH_REMATCH[2]}"
        host="${BASH_REMATCH[5]}"
        body="${BASH_REMATCH[6]}"
        ts="$(iso_to_syslog_ts "$ymd" "$hms")"

        out_line="${pri}${ts} ${host} ${body}"
    else
        out_line="${pri}${rest}"
    fi

    # Remove a known duplicate segment if upstream formatting produced it.
    while [[ "$out_line" == *"auditd-info type=PROCTITLE auditd-info type=PROCTITLE"* ]]; do
        out_line="${out_line/auditd-info type=PROCTITLE auditd-info type=PROCTITLE/auditd-info type=PROCTITLE}"
    done

    out_line="${out_line} decoded_proctitle=\"${DECODED_ESCAPED}\""

    dbg "OUT: $out_line"
    send_udp "$out_line"
done

exit 0
