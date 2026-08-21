# Auditd PROCTITLE Decoder for rsyslog

> **English documentation**  
> Türkçe dokümantasyon: [`README_TR.md`](README_TR.md)

A small rsyslog enrichment utility for Linux `auditd` events.

Linux Audit Framework `type=PROCTITLE` events commonly store the process command line in the `proctitle=` field as hexadecimal data. This project decodes that value, adds a human-readable `decoded_proctitle="..."` field, and forwards the enriched event to a SIEM or other remote syslog receiver.

The original `proctitle=` value is preserved.

## Why?

A raw event may contain something similar to:

```text
type=PROCTITLE msg=audit(...) proctitle=2F7573722F62696E2F6375726C002D6B
```

The decoded event becomes:

```text
type=PROCTITLE msg=audit(...) proctitle=2F7573722F62696E2F6375726C002D6B decoded_proctitle="/usr/bin/curl -k"
```

This makes command-line telemetry easier to search, parse, investigate, and use in detection rules without removing the original audit data.

## Architecture

```text
auditd
  |
  v
rsyslog
  |
  +---- normal events -----------------------> existing pipeline
  |
  +---- type=PROCTITLE
          |
          v
        omprog
          |
          v
      decode.sh
          |
          +---- HEX -> ASCII
          +---- NULL bytes -> argv spaces
          +---- whitespace normalization
          +---- decoded_proctitle enrichment
          |
          v
     SIEM / syslog receiver
```

## Features

- Detects `type=PROCTITLE` events.
- Extracts hexadecimal `proctitle=` values.
- Converts auditd NULL-byte argument separators into spaces.
- Replaces non-printable characters with spaces.
- Collapses repeated whitespace.
- Preserves the original `proctitle=` field.
- Adds `decoded_proctitle="..."`.
- Escapes quotes and backslashes in the decoded value.
- Preserves an existing syslog PRI when present.
- Can normalize RFC3339/ISO timestamps into traditional syslog timestamps.
- Avoids re-processing events that already contain `decoded_proctitle=`.
- Supports optional debug logging.
- Uses Bash built-ins only for decoding and UDP forwarding.

## Requirements

- Linux
- Bash
- rsyslog
- rsyslog `omprog` module
- AppArmor utilities if AppArmor is enforcing on the host

The example below was designed for Debian/Ubuntu-style systems. Paths can differ on other distributions.

## Installation

### 1. Install the required packages

```bash
sudo apt update
sudo apt install -y rsyslog apparmor-utils
```

Confirm that rsyslog is running:

```bash
systemctl status rsyslog
```

## 2. Install the decoder

Copy `decode.sh` to:

```text
/usr/local/bin/decode.sh
```

Then make it executable:

```bash
sudo chmod 750 /usr/local/bin/decode.sh
sudo chown root:root /usr/local/bin/decode.sh
```

## 3. Configure the destination

The script is intentionally vendor-neutral.

The following environment variables are supported:

| Variable | Default | Description |
|---|---|---|
| `SIEM_HOST` | `127.0.0.1` | Destination hostname or IP |
| `SIEM_PORT` | `514` | Destination UDP port |
| `DEFAULT_PRI` | `<182>` | PRI used when the input event has no PRI |
| `DEBUG` | `0` | Set to `1` to enable debug logging |
| `DEBUG_FILE` | `/var/log/decode_proctitle.debug` | Preferred debug log path |

For rsyslog `omprog`, the cleanest approach is to use a small wrapper so destination settings are not hard-coded into the decoder.

Create:

```text
/usr/local/bin/decode-proctitle-wrapper.sh
```

with:

```bash
#!/usr/bin/env bash

export SIEM_HOST="192.0.2.10"
export SIEM_PORT="514"
export DEFAULT_PRI="<182>"
export DEBUG="0"

exec /usr/local/bin/decode.sh
```

Replace `192.0.2.10` with your actual SIEM/syslog destination.

Then:

```bash
sudo chmod 750 /usr/local/bin/decode-proctitle-wrapper.sh
sudo chown root:root /usr/local/bin/decode-proctitle-wrapper.sh
```

> `192.0.2.0/24` is an IANA documentation range and is used here only as an example.

## 4. AppArmor configuration

If AppArmor is enforcing the rsyslog profile, rsyslog must be allowed to execute the wrapper and decoder.

Open:

```bash
sudo vi /etc/apparmor.d/usr.sbin.rsyslogd
```

Add the required execution rules inside the rsyslog profile:

```text
/usr/local/bin/decode-proctitle-wrapper.sh rix,
/usr/local/bin/decode.sh rix,
/usr/bin/bash ix,
/bin/bash ix,
```

Depending on the distribution, Bash may exist only at `/usr/bin/bash` or `/bin/bash`.

Check it with:

```bash
command -v bash
```

Reload the AppArmor profile:

```bash
sudo apparmor_parser -r /etc/apparmor.d/usr.sbin.rsyslogd
```

Then check for AppArmor denials if necessary:

```bash
sudo journalctl -k | grep -i apparmor
```

or:

```bash
sudo dmesg | grep -i apparmor
```

## 5. Configure rsyslog

Create a dedicated configuration file rather than modifying the main file directly:

```text
/etc/rsyslog.d/40-auditd-proctitle-decoder.conf
```

Add:

```text
module(load="omprog")

if (
    $rawmsg contains "type=PROCTITLE"
    and $rawmsg contains "proctitle="
    and not ($rawmsg contains "decoded_proctitle=")
) then {
    action(
        type="omprog"
        binary="/usr/local/bin/decode-proctitle-wrapper.sh"
    )

    stop
}
```

### Important note about `stop`

`stop` prevents the matching event from continuing through later rsyslog rules.

That is appropriate when the enriched event sent by this project should replace the original PROCTITLE event in the downstream SIEM pipeline.

If you want both the original and enriched PROCTITLE events to continue to separate destinations, remove `stop` and design the surrounding rsyslog rules accordingly.

## 6. Validate the rsyslog configuration

Before restarting rsyslog:

```bash
sudo rsyslogd -N1
```

A successful validation should end without configuration errors.

## 7. Restart rsyslog

```bash
sudo systemctl restart rsyslog
```

Verify:

```bash
sudo systemctl status rsyslog
```

## Testing

### Direct decoder test

You can test the script without rsyslog.

Start a temporary UDP listener on another host, or point `SIEM_HOST` to a test syslog receiver.

Then run:

```bash
printf '%s\n' \
'<182>2026-08-20T22:10:11.123456+03:00 linux01 auditd-info type=PROCTITLE msg=audit(1234567890.123:100): proctitle=2F7573722F62696E2F6375726C002D6B' \
| SIEM_HOST=192.0.2.10 SIEM_PORT=514 /usr/local/bin/decode.sh
```

Expected enriched portion:

```text
decoded_proctitle="/usr/bin/curl -k"
```

### Generate a real audit event

If auditd is configured to record execution telemetry, run a harmless command such as:

```bash
/usr/bin/printf 'proctitle-test\n'
```

Then inspect audit logs or your SIEM for a matching `type=PROCTITLE` event.

## Debugging

Enable debug mode in the wrapper:

```bash
export DEBUG="1"
```

The decoder first tries:

```text
/var/log/decode_proctitle.debug
```

If the rsyslog/AppArmor context cannot write there, it falls back to:

```text
/tmp/decode_proctitle.debug
```

Example:

```bash
sudo tail -f /tmp/decode_proctitle.debug
```

Typical entries:

```text
IN:  <raw event>
OUT: <enriched event>
```

## Troubleshooting

### rsyslog fails to restart

Validate the configuration:

```bash
sudo rsyslogd -N1
```

Then inspect:

```bash
sudo journalctl -u rsyslog -n 100 --no-pager
```

### Script works manually but not from rsyslog

Check AppArmor first:

```bash
sudo journalctl -k | grep -i apparmor
```

Also verify permissions:

```bash
ls -l /usr/local/bin/decode.sh
ls -l /usr/local/bin/decode-proctitle-wrapper.sh
```

### Events are decoded but do not reach the SIEM

Check basic connectivity from the Linux host:

```bash
nc -zvu 192.0.2.10 514
```

UDP checks cannot prove end-to-end delivery, so also validate on the receiving side.

If your environment requires reliable delivery, consider replacing UDP forwarding with TCP or TLS rather than using `/dev/udp`.

### Duplicate events appear

Review whether the original PROCTITLE event is already forwarded by another rsyslog rule.

The supplied example uses:

```text
stop
```

to prevent the original matching event from continuing through later rules.

### `decoded_proctitle` is empty or malformed

Confirm that the incoming event contains a hexadecimal value:

```text
proctitle=<hex>
```

The decoder intentionally ignores non-hex values.

## Security considerations

This project executes an external program from rsyslog using `omprog`.

Recommended practices:

- Keep the decoder owned by `root`.
- Do not make the script writable by the rsyslog service account.
- Restrict file permissions.
- Keep AppArmor permissions as narrow as possible.
- Do not hard-code production credentials in the script.
- Prefer authenticated TLS transport for untrusted or routed networks.
- Test changes in a non-production environment first.
- Review your existing rsyslog routing before using `stop`.

This utility performs enrichment only. It does not validate whether the decoded command itself is benign or malicious.

## Repository layout

```text
auditd-proctitle-decoder/
├── decode.sh
└── README.md
```

## Example use cases

The enriched field can make it easier to build detections for patterns such as:

```text
decoded_proctitle contains "curl"
decoded_proctitle contains "wget"
decoded_proctitle contains "chmod"
decoded_proctitle contains "base64"
```

These strings should not be treated as malicious by themselves. Detection logic should include appropriate context, allow-listing, user/process relationships, and other telemetry.

## License

This project is licensed under the [MIT License](LICENSE).

Copyright (c) 2026 Sergen Yanmis.
