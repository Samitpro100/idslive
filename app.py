"""Linux-friendly live packet IDS for the supplied dashboard.

Captures only packets visible to the selected local interface. It does not create,
inject, replay, or scan packets. Only packet metadata and an optional HTTP request
line are sent to the dashboard; full payloads are not stored.
"""
from __future__ import annotations

import os
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Optional
from log_monitor import start_log_monitor
from flask import Flask, jsonify, send_from_directory
from flask_socketio import SocketIO, emit
from scapy.all import AsyncSniffer, IP, IPv6, TCP, UDP, ICMP, Raw, get_if_list

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__, static_folder=BASE_DIR)
app.config["SECRET_KEY"] = os.environ.get("IDS_SECRET_KEY", "local-ids-change-me")
socketio = SocketIO(app, cors_allowed_origins=[], async_mode="threading")

DEFAULT_PORT_SCAN_THRESHOLD = 5
DEFAULT_SYN_THRESHOLD = 25
WINDOW_SECONDS = 3.0
ALERT_COOLDOWN_SECONDS = 10.0
MAX_RECENT_PACKETS = 500

state_lock = threading.RLock()
sniffer: Optional[AsyncSniffer] = None
capture_active = False
selected_interface = os.environ.get("IDS_INTERFACE", "auto")
# Empty target IP means no host filter. Port 0 means all ports.
capture_filter = {"target_ip": os.environ.get("IDS_TARGET_IP", "").strip(),
                  "server_port": int(os.environ.get("IDS_SERVER_PORT", "0") or 0)}
total_packets = 0
config = {"portScanRate": DEFAULT_PORT_SCAN_THRESHOLD, "synFloodRate": DEFAULT_SYN_THRESHOLD}
port_events = defaultdict(deque)
syn_events = defaultdict(deque)
last_alert = {}


def utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%H:%M:%S")


def _trim(events: deque, now: float, window: float) -> None:
    while events and now - events[0][0] > window:
        events.popleft()


def packet_to_record(packet) -> Optional[dict]:
    """Return IP/TCP/UDP/ICMP metadata; never return arbitrary payload bytes."""
    if IP in packet:
        src, dst, version = packet[IP].src, packet[IP].dst, "IPv4"
    elif IPv6 in packet:
        src, dst, version = packet[IPv6].src, packet[IPv6].dst, "IPv6"
    else:
        return None

    proto, port, flags = version, "-", "-"
    app_protocol = ""
    src_port = None
    dst_port = None
    http_line = ""
    if TCP in packet:
        tcp = packet[TCP]
        src_port, dst_port = int(tcp.sport), int(tcp.dport)
        # Keep transport protocol accurate; application hints are separate.
        proto = "TCP"
        port = dst_port
        flags = str(tcp.flags)
        if src_port in (80, 8080, 8000) or dst_port in (80, 8080, 8000):
            app_protocol = "HTTP"
        elif src_port in (20, 21, 990) or dst_port in (20, 21, 990):
            app_protocol = "FTP"
        elif src_port == 22 or dst_port == 22:
            app_protocol = "SSH"
        # Display only a bounded HTTP request/status line for plaintext HTTP.
        # HTTPS content is encrypted and is intentionally not decoded.
        if Raw in packet and app_protocol == "HTTP":
            try:
                first_line = bytes(packet[Raw].load).split(b"\r\n", 1)[0][:240].decode("latin-1", "replace")
                if first_line.startswith(("GET ", "POST ", "PUT ", "PATCH ", "DELETE ", "HEAD ", "OPTIONS ", "HTTP/1.")):
                    http_line = first_line
            except Exception:
                pass
        if http_line:
            flags = http_line
    elif UDP in packet:
        udp = packet[UDP]
        src_port, dst_port = int(udp.sport), int(udp.dport)
        port = dst_port
        proto = "UDP"
        if src_port in (20, 21, 990) or dst_port in (20, 21, 990):
            app_protocol = "FTP"
    elif ICMP in packet:
        proto = "ICMP"

    return {"timestamp": utc_stamp(), "srcIP": src, "dstIP": dst,
            "protocol": proto, "port": port, "srcPort": src_port,
            "dstPort": dst_port, "pktLen": int(len(packet)),
            "flags": flags, "httpLine": http_line,
            "appProtocol": app_protocol, "status": "CLEAN"}


def packet_matches_filter(record: dict) -> bool:
    with state_lock:
        target_ip = capture_filter["target_ip"]
        server_port = capture_filter["server_port"]
    if target_ip and target_ip not in (record["srcIP"], record["dstIP"]):
        return False
    if server_port:
        ports = (record.get("srcPort"), record.get("dstPort"))
        if server_port not in ports:
            return False
    return True


def analyze_and_emit(packet) -> None:
    global total_packets
    try:
        record = packet_to_record(packet)
        if record is None or not packet_matches_filter(record):
            return
        now = time.time()
        src, dst = record["srcIP"], record["dstIP"]
        alerts = []
        with state_lock:
            total_packets += 1
            if TCP in packet:
                dport = int(packet[TCP].dport)
                flags = int(packet[TCP].flags)
                target_key = (src, dst)
                # Only initial SYN packets (SYN set, ACK unset) count toward these rules.
                if flags & 0x02 and not flags & 0x10:
                    port_events[target_key].append((now, dport))
                    _trim(port_events[target_key], now, WINDOW_SECONDS)
                    unique_ports = {p for _, p in port_events[target_key]}
                    threshold = max(2, int(config["portScanRate"]))
                    key = (src, dst, "Port Scanning")
                    if len(unique_ports) >= threshold and now - last_alert.get(key, 0) >= ALERT_COOLDOWN_SECONDS:
                        last_alert[key] = now
                        record["status"] = "ALERT"
                        alerts.append({"id": f"{src}-{int(now*1000)}", "timestamp": record["timestamp"],
                            "srcIP": src, "dstIP": dst, "threatType": "Port Scanning", "severity": "HIGH",
                            "action": "Logged & Alerted", "details": f"Observed {len(unique_ports)} unique TCP SYN destination ports from this source to this target in {WINDOW_SECONDS:.0f} seconds."})
                    syn_events[target_key].append((now, 1))
                    _trim(syn_events[target_key], now, 2.0)
                    syn_threshold = max(5, int(config["synFloodRate"]))
                    key = (src, dst, "Possible SYN Flood")
                    if len(syn_events[target_key]) >= syn_threshold and now - last_alert.get(key, 0) >= ALERT_COOLDOWN_SECONDS:
                        last_alert[key] = now
                        record["status"] = "ALERT"
                        alerts.append({"id": f"{src}-{int(now*1000)}-syn", "timestamp": record["timestamp"],
                            "srcIP": src, "dstIP": dst, "threatType": "Possible SYN Flood", "severity": "HIGH",
                            "action": "Logged & Alerted", "details": f"Observed {len(syn_events[target_key])} initial TCP SYN packets from this source to this target in 2 seconds. Heuristic only; not proof of a successful attack."})
        socketio.emit("packet", record)
        for alert in alerts:
            socketio.emit("threat", alert)
        if total_packets % 25 == 0:
            socketio.emit("server_stats", {"total_packets": total_packets})
    except Exception as exc:
        app.logger.exception("Packet processing failed: %s", exc)


def stop_capture() -> None:
    global sniffer, capture_active
    with state_lock:
        current, sniffer, capture_active = sniffer, None, False
    if current is not None:
        try:
            current.stop(join=False)
        except Exception:
            pass
    socketio.emit("capture_status", {"active": False, "message": "Packet capture stopped"})


def start_capture(interface: Optional[str] = None) -> None:
    global sniffer, capture_active, selected_interface
    if interface is not None:
        selected_interface = interface or "auto"
    with state_lock:
        if capture_active and sniffer is not None:
            return
        iface = None if selected_interface == "auto" else selected_interface
        try:
            new_sniffer = AsyncSniffer(iface=iface, prn=analyze_and_emit, store=False, promisc=True)
            new_sniffer.start()
            sniffer, capture_active = new_sniffer, True
        except Exception as exc:
            sniffer, capture_active = None, False
            socketio.emit("capture_error", {"message": f"Could not start capture on {selected_interface}: {exc}. On Kali, install libpcap and run with sudo; choose the interface that actually carries the Apache traffic."})
            return
    label = "default interface (auto)" if selected_interface == "auto" else selected_interface
    socketio.emit("capture_status", {"active": True, "message": f"Capturing visible traffic on {label}; host/port filters are applied in the IDS"})


@app.route("/")
def dashboard():
    return send_from_directory(BASE_DIR, "ids_live_dashboard.html")


@app.route("/api/health")
def health():
    with state_lock:
        return jsonify({"ok": True, "capture_active": capture_active, "interface": selected_interface,
                        "total_packets": total_packets, "filter": dict(capture_filter)})


@socketio.on("connect")
def on_connect():
    emit("capture_status", {"active": capture_active, "message": "Backend connected"})
    emit("server_stats", {"total_packets": total_packets})
    emit("capture_filter", dict(capture_filter))


@socketio.on("get_interfaces")
def on_get_interfaces():
    try:
        interfaces = ["auto"] + sorted(set(get_if_list()))
    except Exception:
        interfaces = ["auto"]
    emit("interfaces", interfaces)


@socketio.on("start_capture")
def on_start_capture():
    start_capture()


@socketio.on("stop_capture")
def on_stop_capture():
    stop_capture()


@socketio.on("set_interface")
def on_set_interface(data):
    name = (data or {}).get("interface", "auto")
    if name != "auto" and name not in set(get_if_list()):
        emit("capture_error", {"message": "Unknown interface. Refresh and select an interface listed by Scapy."})
        return
    stop_capture()
    start_capture(name)


@socketio.on("set_capture_filter")
def on_set_capture_filter(data):
    data = data or {}
    target_ip = str(data.get("target_ip", "")).strip()
    port_text = str(data.get("server_port", "0")).strip()
    if target_ip and any(ch not in "0123456789abcdefABCDEF:." for ch in target_ip):
        emit("capture_error", {"message": "Enter a valid IPv4/IPv6 address, or leave the host filter blank."})
        return
    try:
        port = int(port_text or 0)
        if not 0 <= port <= 65535:
            raise ValueError
    except ValueError:
        emit("capture_error", {"message": "Port must be between 0 and 65535; use 0 for all ports."})
        return
    with state_lock:
        capture_filter.update(target_ip=target_ip, server_port=port)
    emit("capture_filter", dict(capture_filter), broadcast=True)
    emit("capture_status", {"active": capture_active, "message": f"Filter applied: host={target_ip or 'any'}, port={port or 'any'}"}, broadcast=True)


@socketio.on("set_config")
def on_set_config(data):
    if not isinstance(data, dict):
        return
    with state_lock:
        for key in ("portScanRate", "synFloodRate"):
            if key in data:
                try:
                    config[key] = max(2, min(10000, int(data[key])))
                except (TypeError, ValueError):
                    pass


@socketio.on("disconnect")
def on_disconnect():
    pass


if __name__ == "__main__":
    host = os.environ.get("IDS_HOST", "127.0.0.1")
    port = int(os.environ.get("IDS_PORT", "5000"))
    print(f"IDS dashboard: http://127.0.0.1:{port}")
    print("No synthetic traffic is generated. Start Apache or make normal authorized requests to create real traffic.")
    print("Use only on systems/networks you own or are authorized to monitor.")
    start_log_monitor(socketio, app)
    socketio.run(app, host=host, port=port, debug=False, allow_unsafe_werkzeug=True)
