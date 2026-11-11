# Useful log queries

Cowrie writes one JSON event per line to `cowrie.json`, inside the `cowrie-var` volume.

```bash
LOG=/var/lib/docker/volumes/cowrie_cowrie-var/_data/log/cowrie/cowrie.json
```

| Goal | Command |
|---|---|
| Last 3 events, pretty-printed | `sudo tail -n 3 $LOG \| jq` |
| Commands typed by attackers | `sudo cat $LOG \| jq -r 'select(.eventid=="cowrie.command.input") \| .input'` |
| Successful logins (user / password) | `sudo cat $LOG \| jq -r 'select(.eventid=="cowrie.login.success") \| "\(.username) / \(.password)"'` |
| Failed logins | `sudo cat $LOG \| jq -r 'select(.eventid=="cowrie.login.failed") \| "\(.username) / \(.password)"'` |
| Top 10 passwords tried | `sudo cat $LOG \| jq -r 'select(.eventid \| startswith("cowrie.login")) \| .password' \| sort \| uniq -c \| sort -rn \| head` |
| Top 10 source IPs | `sudo cat $LOG \| jq -r 'select(.eventid=="cowrie.session.connect") \| .src_ip' \| sort \| uniq -c \| sort -rn \| head` |

## Main event types

| `eventid` | Meaning |
|---|---|
| `cowrie.session.connect` | New connection |
| `cowrie.login.success` / `cowrie.login.failed` | Login attempt |
| `cowrie.command.input` | Command typed in the fake shell |
| `cowrie.session.file_download` | File fetched by the attacker (wget/curl) |
| `cowrie.session.closed` | End of session |
