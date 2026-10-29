
"""Monitor Apache and SSH logs and emit alerts to the existing IDS dashboard."""
import os
import re
import time
import threading
import subprocess
from collections import defaultdict, deque
from datetime import datetime, timezone

_started = False
_lock = threading.Lock()
_events = defaultdict(deque)
_last_alert = {}

WINDOW = 60
COOLDOWN = 60

ACCESS_RE = re.compile(
    r'^(\S+) \S+ \S+ \[[^\]]+\] "([A-Z]+)\s+(\S+)(?:\s+HTTP/[^"]*)?"\s+(\d{3})'
)
CLIENT_RE = re.compile(r'\bclient ([0-9a-fA-F:.]+)(?::\d+)?')
FAILED_RE = re.compile(
    r'Failed password for (?:invalid user )?\S+ from ([0-9a-fA-F:.]+)'
)
INVALID_USER_RE = re.compile(
    r'Invalid user \S+ from ([0-9a-fA-F:.]+)'
)
SUCCESS_RE = re.compile(
    r'Accepted (?:password|publickey|keyboard-interactive/pam) for '
    r'\S+ from ([0-9a-fA-F:.]+)'
)
FTP_FAILED_RE = re.compile(
    r'(?:FAIL LOGIN|LOGIN FAILED|authentication failure|530 Login incorrect|Login failed)',
    re.IGNORECASE,
)
FTP_SUCCESS_RE = re.compile(
    r'(?:OK LOGIN|LOGIN OK|230 Login successful|Login successful)', re.IGNORECASE
)
FTP_IP_RE = re.compile(
    r'(?:from|client|REMOTE HOST:|rip=)\s*[=:]?\s*[\"\']?([0-9a-fA-F:.]+)', re.IGNORECASE
)


def timestamp():
    return datetime.now(timezone.utc).strftime("%H:%M:%S")


def alert(socketio, app, source, destination, kind, severity, details):
    now = time.time()
    key = (source, kind)

    with _lock:
        if now - _last_alert.get(key, 0) < COOLDOWN:
            return
        _last_alert[key] = now

    item = {
        "id": f"log-{int(now * 1000)}",
        "timestamp": timestamp(),
        "srcIP": source or "Unknown",
        "dstIP": destination,
        "threatType": kind,
        "severity": severity,
        "action": "Logged & Alerted",
        "details": details,
    }

    app.logger.warning("IDS LOG ALERT: %s", item)
    socketio.emit("threat", item)


def count_event(source, category, now=None):
    now = now or time.time()
    key = (source, category)
    events = _events[key]
    events.append(now)

    while events and now - events[0] > WINDOW:
        events.popleft()

    return len(events)


def process_apache_access(line, socketio, app):
    match = ACCESS_RE.search(line)
    if not match:
        return

    ip, method, path, status_text = match.groups()
    status = int(status_text)
    now = time.time()
    lower_path = path.lower()

    # Common sensitive paths sometimes probed by scanners.
    suspicious_paths = (
        "/.env", "/.git", "/wp-admin", "/phpmyadmin",
        "/server-status", "/etc/passwd", "/cgi-bin",
    )

    if (
        lower_path.startswith(suspicious_paths)
        or "../" in lower_path
        or "%2e%2e" in lower_path
    ):
        alert(
            socketio, app, ip, "Apache",
            "Suspicious Apache Path", "MEDIUM",
            f"Request to suspicious path: {path} ({method})",
        )

    if status in (401, 403):
        count = count_event(ip, f"http-denied-{status}", now)
        if count >= 8:
            alert(
                socketio, app, ip, "Apache",
                "Repeated HTTP Access Denials", "MEDIUM",
                f"{count} HTTP {status} responses from this IP within {WINDOW} seconds.",
            )

    if status == 404:
        count = count_event(ip, "http-404", now)
        if count >= 15:
            alert(
                socketio, app, ip, "Apache",
                "Possible Web Path Probing", "MEDIUM",
                f"{count} HTTP 404 responses from this IP within {WINDOW} seconds.",
            )

    count = count_event(ip, "http-requests", now)
    if count >= 60:
        alert(
            socketio, app, ip, "Apache",
            "High HTTP Request Rate", "MEDIUM",
            f"At least 60 logged requests from this IP within {WINDOW} seconds.",
        )


def process_apache_error(line, socketio, app):
    match = CLIENT_RE.search(line)
    ip = match.group(1) if match else "Unknown"

    lower = line.lower()

    if "client denied by server configuration" in lower:
        alert(
            socketio, app, ip, "Apache",
            "Apache Access Denied", "MEDIUM",
            line.strip()[:300],
        )
        return

    if any(word in lower for word in (
        "permission denied", "script not found",
        "malformed request", "request failed",
    )):
        count = count_event(ip, "apache-errors")
        if count >= 10:
            alert(
                socketio, app, ip, "Apache",
                "Repeated Apache Errors", "MEDIUM",
                f"Repeated request-related errors. Latest log: {line.strip()[:220]}",
            )


def process_ssh(line, socketio, app):
    failed = FAILED_RE.search(line) or INVALID_USER_RE.search(line)

    if failed:
        ip = failed.group(1)
        count = count_event(ip, "ssh-failed")
        if count >= 5:
            alert(
                socketio, app, ip, "SSH",
                "Possible SSH Brute-Force Attempt", "HIGH",
                f"{count} failed or invalid-user SSH authentication entries within {WINDOW} seconds.",
            )
        return

    success = SUCCESS_RE.search(line)
    if success:
        ip = success.group(1)
        alert(
            socketio, app, ip, "SSH",
            "Successful SSH Login", "LOW",
            "SSH authentication succeeded. Verify that this login was authorized.",
        )



def process_ftp(line, socketio, app):
    """Detect repeated FTP authentication failures and successful logins."""
    text = line.strip()
    if not text:
        return
    ip_match = FTP_IP_RE.search(text)
    ip = ip_match.group(1).rstrip(":") if ip_match else "Unknown"
    if FTP_FAILED_RE.search(text):
        count = count_event(ip, "ftp-failed")
        if count >= 5:
            alert(socketio, app, ip, "FTP", "Possible FTP Brute-Force Attempt", "HIGH",
                  f"{count} failed FTP authentication entries within {WINDOW} seconds.")
    elif FTP_SUCCESS_RE.search(text):
        alert(socketio, app, ip, "FTP", "Successful FTP Login", "LOW",
              "FTP authentication succeeded. Verify that this login was authorized.")

def follow_log(path, kind, socketio, app):
    """Follow new log entries; GNU tail -F also follows log rotation."""
    while True:
        try:
            process = subprocess.Popen(
                ["tail", "-n", "0", "-F", path],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                bufsize=1,
            )

            app.logger.info("Monitoring log: %s", path)

            for line in process.stdout:
                if kind == "apache_access":
                    process_apache_access(line, socketio, app)
                elif kind == "apache_error":
                    process_apache_error(line, socketio, app)
                elif kind == "ssh":
                    process_ssh(line, socketio, app)
                elif kind == "ftp":
                    process_ftp(line, socketio, app)

        except Exception as exc:
            app.logger.warning("Log monitor problem for %s: %s", path, exc)

        time.sleep(5)


def follow_ssh_journal(socketio, app):
    """Fallback when /var/log/auth.log is not available."""
    while True:
        try:
            process = subprocess.Popen(
                ["journalctl", "-f", "-u", "ssh.service", "-o", "cat"],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                bufsize=1,
            )

            app.logger.info("Monitoring SSH systemd journal")

            for line in process.stdout:
                process_ssh(line, socketio, app)

        except Exception as exc:
            app.logger.warning("SSH journal monitor problem: %s", exc)

        time.sleep(5)



def follow_ftp_journal(socketio, app):
    """Attach to installed FTP daemon journals; retry when none is available."""
    while True:
        attached = False
        try:
            # Follow the system journal without pinning to vsftpd: installations
            # commonly use vsftpd, ProFTPD, or Pure-FTPd. The parser only emits
            # alerts for recognized FTP login messages.
            process = subprocess.Popen(
                ["journalctl", "-f", "-o", "cat", "--since", "now"],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1,
            )
            app.logger.info("Monitoring system journal for FTP authentication events")
            attached = True
            for line in process.stdout:
                process_ftp(line, socketio, app)
        except Exception as exc:
            app.logger.warning("FTP journal monitor unavailable: %s", exc)
        if not attached:
            time.sleep(5)

def start_log_monitor(socketio, app):
    global _started

    with _lock:
        if _started:
            return
        _started = True

    logs = [
        ("/var/log/apache2/access.log", "apache_access"),
        ("/var/log/apache2/error.log", "apache_error"),
    ]
    ftp_candidates = (
        "/var/log/vsftpd.log", "/var/log/xferlog",
        "/var/log/proftpd/proftpd.log", "/var/log/pure-ftpd/transfer.log",
    )
    ftp_logs_found = False
    for ftp_path in ftp_candidates:
        if os.path.exists(ftp_path):
            logs.append((ftp_path, "ftp"))
            ftp_logs_found = True

    for path, kind in logs:
        threading.Thread(
            target=follow_log,
            args=(path, kind, socketio, app),
            daemon=True,
        ).start()

    if os.path.exists("/var/log/auth.log"):
        ssh_target = ("/var/log/auth.log", "ssh")
        threading.Thread(
            target=follow_log,
            args=(*ssh_target, socketio, app),
            daemon=True,
        ).start()
    else:
        threading.Thread(
            target=follow_ssh_journal,
            args=(socketio, app),
            daemon=True,
        ).start()

    # Also watch the system journal even when a file such as xferlog exists:
    # transfer logs do not necessarily contain FTP authentication events.
    threading.Thread(target=follow_ftp_journal, args=(socketio, app), daemon=True).start()

    app.logger.info("Apache, SSH, and FTP log monitors started")

