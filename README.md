<div align="center">

# 📬 miab-radar

### High-signal health, deliverability and security diagnostics for Mail-in-a-Box

<img src="https://img.shields.io/badge/Bash-4%2B-121011?style=for-the-badge&logo=gnubash&logoColor=white" alt="Bash 4+">
<img src="https://img.shields.io/badge/Mail--in--a--Box-ready-2563eb?style=for-the-badge" alt="Mail-in-a-Box">
<img src="https://img.shields.io/badge/status-active-16a34a?style=for-the-badge" alt="Active">
<img src="https://img.shields.io/github/license/Anton-Babaskin/miab-radar?style=for-the-badge&color=0ea5e9" alt="License">

<a href="#-quick-run">Quick Run</a> · <a href="#-coverage">Coverage</a> · <a href="#-automation">Automation</a> · <a href="#exit-codes">Exit Codes</a>

</div>

---

## ⚡ Quick Run

```bash
git clone https://github.com/Anton-Babaskin/miab-radar.git
cd miab-radar
chmod +x miab-radar.sh
sudo ./miab-radar.sh
```

Inspect a wider 48-hour log window:

```bash
sudo ./miab-radar.sh 48
```

> [!NOTE]
> Run directly on the Mail-in-a-Box host. The tool is terminal-first, dependency-light and focused on actionable findings.

## 🎯 What it is for

`miab-radar` turns Mail-in-a-Box service state, queues, logs, DNS, TLS and security signals into a prioritized **OK / WARN / FAIL** view. It is built for operational troubleshooting—not dashboards or long-term metrics storage.

## 🔭 Coverage

| Area | Signals |
|---|---|
| 📮 Mail flow | active/deferred/stuck queue, bounces, deferrals, senders, recipients and SMTP behavior |
| 🌐 DNS & reputation | MX, SPF, DKIM, DMARC, PTR and common DNSBL checks |
| 🔐 Security | Fail2Ban, brute-force signals, SSH posture and open-relay protection |
| 🔒 TLS | SMTP, IMAPS and HTTPS certificates, expiry and STARTTLS |
| 🖥️ Host health | Postfix/Dovecot/Nginx services, disk, inodes, mailboxes and backup freshness |

## 📦 Optional global install

```bash
sudo ./install.sh
sudo miab-radar
```

The installer copies the executable to `/usr/local/bin/miab-radar`.

## ⏱️ Automation

Example cron entry for a 30-minute health snapshot:

```cron
*/30 * * * * /usr/local/bin/miab-radar > /var/log/miab-radar.log
```

For automation, consume the exit code and preserve the full report for diagnosis.

## Exit Codes

| Code | Meaning |
|---:|---|
| `0` | All checks passed |
| `1` | Warnings are present |
| `2` | Critical findings detected |

## Requirements

- Mail-in-a-Box on Ubuntu/Debian
- Bash 4+
- Root privileges for full logs and service visibility
- Standard system and DNS utilities used by Mail-in-a-Box

## Project philosophy

- **Bash:** deterministic, inspectable checks
- **Logs:** the source of truth for mail flow
- **Output:** concise findings with next actions
- **Overhead:** no agents, database or heavy runtime

## Related tools

- [mail-sec-audit](https://github.com/Anton-Babaskin/mail-sec-audit) — broad security posture across different Linux mail stacks.
- [smtp-egress-audit](https://github.com/Anton-Babaskin/smtp-egress-audit) — focused attribution of abnormal outbound SMTP connections.
- [mail_analyzer.sh](https://github.com/Anton-Babaskin/mail_analyzer.sh) — deeper Postfix log statistics.

## License

MIT — see [LICENSE](LICENSE).

## Author

Anton Babaskin
