# VM evidence audit

Read-only collector for one Ubuntu VM. It records DNS, HTTP/HTTPS, TLS SNI, Tailscale, local account state, and scheduled tasks.

It does not change passwords, users, SSH, firewall rules, or services. It cannot prove that a person acted intentionally.

## Run on the VM

```bash
curl -fsSL -o vm-evidence-audit.sh https://raw.githubusercontent.com/SKuytov/vm-evidence-audit/main/vm-evidence-audit.sh
bash vm-evidence-audit.sh
```

The default test target is `skuytov.eu` and `/grafik/admin.php`. Override either one if needed:

```bash
bash vm-evidence-audit.sh --no-capture
bash vm-evidence-audit.sh --since "2026-09-01" --target skuytov.eu --path /grafik/admin.php
```

The report is saved in `~/vm-audit-<timestamp>/`. For interpretation, copy `FINDINGS.txt` and `IT-NOTE.txt` only. Do not send passwords, private keys, password hashes, or `/etc/shadow`.
