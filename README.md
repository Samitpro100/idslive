# Live Network IDS Dashboard (Kali Linux)

This project combines passive Scapy packet observation with Apache, SSH, and FTP
log monitoring. It sends packet metadata and detected alerts to the existing
Flask-SocketIO dashboard. It does not generate, replay, or scan traffic.

## Included files

- `app.py` — Flask/Socket.IO server, Scapy capture, TCP/UDP protocol classification,
  initial-SYN port-scan/SYN-flood heuristics, host/port filters, and health endpoint.
- `log_monitor.py` — Apache access/error, SSH authentication, and FTP authentication
  log monitoring.
- `ids_live_dashboard.html` — dashboard UI.
- `requirements.txt` — Python dependencies.

## Run on Kali Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
sudo .venv/bin/python app.py
```

Open `http://127.0.0.1:5000`. Keep the dashboard bound to localhost unless you
intentionally configure and secure remote access. Choose the network interface that
carries the traffic, then start capture.

Packet capture typically requires root privileges. Apache/SSH/FTP log monitoring
also needs permission to read the relevant logs or system journal. The app tries
these sources:

- Apache: `/var/log/apache2/access.log` and `/var/log/apache2/error.log`
- SSH: `/var/log/auth.log`, or the `ssh.service` systemd journal if the file is absent
- FTP: common vsftpd/ProFTPD/Pure-FTPd log files plus the system journal

For FTP authentication events, the FTP daemon must actually write login events to a
log or the system journal. A transfer-only `xferlog` may not include authentication
success/failure details. Log formats differ by daemon and configuration.

## Check the backend

```bash
curl http://127.0.0.1:5000/api/health
```

The JSON should report `"ok": true`. `capture_active` becomes true after capture is
started from the dashboard, and `total_packets` increases when packets match the
selected filters.

## What the detection rules do

- **TCP/UDP:** transport protocol stays `TCP` or `UDP`; application hints such as
  HTTP, FTP, and SSH are separate metadata.
- **TCP scan/SYN heuristics:** only initial SYN packets (SYN set, ACK unset) count.
  The rules are rate-based heuristics, not proof of an attack.
- **Apache:** suspicious path probes, repeated 401/403 or 404 responses, high request
  rates, and selected error-log events.
- **SSH:** repeated failed/invalid-user logins and successful authentication events.
- **FTP:** repeated recognized login failures and successful login events from logs.

The dashboard captures only traffic visible to the selected local interface. HTTPS
content is encrypted; this project does not decrypt it. Packet capture does not
replace endpoint logging, firewall controls, or a full production IDS.

## Safe testing

Test only on your own machine or an explicitly authorized lab. Generate normal local
web requests or use controlled authentication attempts against test accounts. Check
the dashboard's packet and threat panels and the application console. Do not expose
an unconfigured FTP service to untrusted networks.
