"""
IDS Backend Server
==================
Reads Zeek conn.log → runs ML models → serves live data via REST API + SSE

Usage:
    pip install flask flask-cors scikit-learn pandas numpy requests
    python backend.py

Make sure ids_binary_model.pkl, ids_multiclass_model.pkl, encoder_mappings.json
are in the same folder as this script.
"""

import os
import json
import time
import pickle
import threading
import queue
import math
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from datetime import datetime
from collections import deque, defaultdict
from flask import Flask, jsonify, Response, stream_with_context
from flask_cors import CORS
import pandas as pd
import numpy as np

# ─── CONFIG ────────────────────────────────────────────────────────────────────
ZEEK_LOG_PATH = "/home/ids/received_conn.log"
BINARY_MODEL_PATH   = "ids_binary_model.pkl"
MULTI_MODEL_PATH    = "ids_multiclass_model.pkl"
ENCODER_PATH        = "encoder_mappings.json"
POLL_INTERVAL       = 1.5
MAX_HISTORY         = 500
MAX_ALERTS          = 200
PORT                = 5050
# ─── OPNSENSE IPS CONFIG ───────────────────────────────────────────────────────
OPNSENSE_HOST = "http://192.168.0.10:80"
OPNSENSE_API_KEY = "180oBUkQCu1dorJdUmBXOZuGlVao63UB+QMQJ55zWg5QGl5hYchCqLfH22QR+1qXiMQL3MK4iEqTdbe7" # API KEY
OPNSENSE_API_SEC = "FAiBaZ0OVnhwmeD5Dhj3/dl2iCxYLRCshps6vS+F2em2AqB0D8u2+badMZ2IQuFa4n7md1GYsdG/OSRP"  # API SECRET KEY
ALIAS_NAME       = "IDS_Blocklist"
BLOCK_CONFIDENCE = 90.0   # auto-block only when confidence >= 90%

WHITELIST = {
    "127.0.0.1",
    "192.168.0.1",    # home router
    "192.168.0.5",    # your main PC — never block yourself
    "192.168.0.10",   # OPNsense — never block this
    "8.8.8.8",
    "8.8.4.4",
}

blocked_ips: set = set()   # in-memory record of currently blocked IPs

# ─── FEATURE COLUMNS (must match training) ────────────────────────────────────
FEATURE_COLS = [
    "duration", "orig_ip_bytes", "resp_ip_bytes", "proto",
    "dest_port_zeek", "conn_state", "history", "orig_pkts"
]

CATEGORICAL_COLS = ["proto", "conn_state", "history"]

# ─── APP SETUP ─────────────────────────────────────────────────────────────────
app = Flask(__name__)
CORS(app)

# ─── GLOBAL STATE ──────────────────────────────────────────────────────────────
state = {
    "connections":    deque(maxlen=MAX_HISTORY),
    "alerts":         deque(maxlen=MAX_ALERTS),
    "stats": {
        "total":      0,
        "attacks":    0,
        "benign":     0,
        "bytes_in":   0,
        "bytes_out":  0,
        "protocols":  defaultdict(int),
        "attack_types": defaultdict(int),
        "per_minute": deque(maxlen=60),
    },
    "sse_clients":    [],
    "lock":           threading.Lock(),
    "binary_model":   None,
    "multi_model":    None,
    "encoders":       {},
    "zeek_file_pos":  0,
    "running":        False,
}

# ─── MODEL LOADING ─────────────────────────────────────────────────────────────
def load_models():
    try:
        with open(BINARY_MODEL_PATH, "rb") as f:
            state["binary_model"] = pickle.load(f)
        print(f"[✓] Binary model loaded: {BINARY_MODEL_PATH}")
    except Exception as e:
        print(f"[✗] Could not load binary model: {e}")

    try:
        with open(MULTI_MODEL_PATH, "rb") as f:
            state["multi_model"] = pickle.load(f)
        print(f"[✓] Multiclass model loaded: {MULTI_MODEL_PATH}")
    except Exception as e:
        print(f"[✗] Could not load multiclass model: {e}")

    try:
        with open(ENCODER_PATH, "r") as f:
            state["encoders"] = json.load(f)
        print(f"[✓] Encoders loaded: {ENCODER_PATH}")
    except Exception as e:
        print(f"[✗] Could not load encoders: {e}")

# ─── FEATURE EXTRACTION FROM ZEEK CONN.LOG ────────────────────────────────────
ZEEK_FIELDS = [
    "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
    "proto", "service", "duration", "orig_bytes", "resp_bytes",
    "conn_state", "local_orig", "local_resp", "missed_bytes",
    "history", "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes",
    "tunnel_parents"
]

def safe_float(val, default=0.0):
    try:
        if val in ("-", "", None):
            return default
        return float(val)
    except:
        return default

def parse_zeek_line(line):
    if line.startswith("#") or not line.strip():
        return None
    parts = line.strip().split("\t")
    if len(parts) < 20:
        return None
    rec = {}
    for i, field in enumerate(ZEEK_FIELDS):
        rec[field] = parts[i] if i < len(parts) else "-"
    return rec

# ─── CATEGORICAL MAPS ─────────────────────────────────────────────────────────
PROTO_MAP = {"icmp": "0", "tcp": "1", "udp": "2"}
CONN_STATE_MAP = {
    "S0": "0", "S1": "1", "SF": "2", "REJ": "3",
    "S2": "4", "S3": "5", "RSTO": "6", "RSTR": "5",
    "RSTOS0": "4", "OTH": "3", "SH": "1", "SHR": "2"
}

def encode_features(rec):
    enc = state["encoders"]
    row = {}
    for col in FEATURE_COLS:
        if col == "dest_port_zeek":
            row[col] = safe_float(rec.get("id.resp_p", "0"))
        elif col == "proto":
            val = rec.get("proto", "-").lower()
            idx = PROTO_MAP.get(val, "3")
            row[col] = safe_float(enc.get("proto", {}).get(idx, "0.0"))
        elif col == "conn_state":
            val = rec.get("conn_state", "-")
            idx = CONN_STATE_MAP.get(val, "0")
            row[col] = safe_float(enc.get("conn_state", {}).get(idx, "0.0"))
        elif col == "history":
            val = rec.get("history", "-")
            hist_enc = enc.get("history", {})
            idx = str(abs(hash(val)) % max(len(hist_enc), 1))
            row[col] = safe_float(hist_enc.get(idx, "0.0"))
        else:
            row[col] = safe_float(rec.get(col, "0"))

    df = pd.DataFrame([row])[FEATURE_COLS]
    return df

# ─── INFERENCE ─────────────────────────────────────────────────────────────────
def run_inference(rec):
    binary_model = state["binary_model"]
    multi_model  = state["multi_model"]

    if binary_model is None:
        return "UNKNOWN", "N/A", 0.0

    try:
        features = encode_features(rec)
        binary_pred = binary_model.predict(features)[0]
        label = str(binary_pred).upper()

        is_attack = label not in ("0", "BENIGN", "NORMAL", "0.0")
        attack_type = "N/A"
        confidence = 0.0

        try:
            proba = binary_model.predict_proba(features)[0]
            confidence = round(float(max(proba)) * 100, 1)
        except:
            confidence = 0.0

        if is_attack and multi_model is not None:
            try:
                multi_pred = multi_model.predict(features)[0]
                attack_type = str(multi_pred)
            except:
                attack_type = "UNKNOWN"

        return ("ATTACK" if is_attack else "NORMAL"), attack_type, confidence

    except Exception as e:
        print(f"[inference error] {e}")
        return "ERROR", "N/A", 0.0

# ─── OPNSENSE API HELPERS ─────────────────────────────────────────────────────
def opnsense_request(method, path, payload=None):
    """Make an authenticated request to the OPNsense API."""
    url = f"{OPNSENSE_HOST}/api/{path}"
    try:
        resp = requests.request(
            method, url,
            auth=(OPNSENSE_API_KEY, OPNSENSE_API_SEC),
            json=payload,
            verify=False,   # OPNsense uses self-signed cert
            timeout=5
        )
        return resp.json()
    except Exception as e:
        print(f"[OPNsense API error] {e}")
        return None

def opnsense_reachable():
    result = opnsense_request("GET", "firewall/alias/searchItem")
    return result is not None

def _get_alias_uuid():
    """Get the UUID of the IDS_Blocklist alias."""
    result = opnsense_request("GET", f"firewall/alias/getAliasUUID/{ALIAS_NAME}")
    if result:
        uuid = result.get("uuid", "")
        if uuid:
            return uuid
    aliases = opnsense_request("GET", "firewall/alias/searchItem")
    if aliases:
        for row in aliases.get("rows", []):
            if row.get("name") == ALIAS_NAME:
                return row.get("uuid", "")
    return None

def _get_alias_ips(uuid):
    """Get current IPs stored in the alias."""
    alias_data = opnsense_request("GET", f"firewall/alias/getAlias/{uuid}")
    if not alias_data:
        return []
    current = alias_data.get("alias", {}).get("content", {})
    if isinstance(current, dict):
        return [v.get("value", "") for v in current.values() if v.get("value", "")]
    return []

def _set_alias_ips(uuid, ip_list):
    """Write ip_list back to the alias using setItem and reconfigure."""
    payload = {
        "alias": {
            "name":        ALIAS_NAME,
            "type":        "host",
            "proto":       "",
            "counters":    "0",
            "enabled":     "1",
            "description": "IDS auto-blocklist",
            "content":     "\n".join(ip_list),
        }
    }
    result = opnsense_request("POST", f"firewall/alias/setItem/{uuid}", payload)
    print(f"[IPS] setItem response: {result}")
    reconf = opnsense_request("POST", "firewall/alias/reconfigure", {})
    print(f"[IPS] reconfigure response: {reconf}")
    
    # Step 2: recreate alias with full IP list
    content = {}
    for i, ip in enumerate(ip_list):
        content[str(i)] = {"value": ip, "description": ""}

    payload = {
        "alias": {
            "name":        ALIAS_NAME,
            "type":        "host",
            "proto":       "",
            "counters":    "0",
            "enabled":     "1",
            "description": "IDS auto-blocklist",
            "content":     content,
        }
    }
    add_result = opnsense_request("POST", "firewall/alias/addAlias", payload)
    print(f"[IPS] addAlias response: {add_result}")

    # Step 3: apply changes
    reconf_result = opnsense_request("POST", "firewall/alias/reconfigure", {})
    print(f"[IPS] reconfigure response: {reconf_result}")

def block_ip(ip: str) -> bool:
    """Add an IP to the OPNsense IDS_Blocklist alias and apply."""
    if ip in WHITELIST or ip in blocked_ips:
        return False
    print(f"[IPS] Blocking {ip} via OPNsense")
    uuid = _get_alias_uuid()
    if not uuid:
        print(f"[IPS] Could not find alias UUID for {ALIAS_NAME}")
        return False
    existing = _get_alias_ips(uuid)
    if ip not in existing:
        existing.append(ip)
        _set_alias_ips(uuid, existing)
    blocked_ips.add(ip)
    print(f"[IPS] ✓ Blocked {ip} in OPNsense")
    return True

def unblock_ip(ip: str) -> bool:
    """Remove an IP from the OPNsense IDS_Blocklist alias."""
    uuid = _get_alias_uuid()
    if not uuid:
        return False
    existing = _get_alias_ips(uuid)
    if ip not in existing:
        blocked_ips.discard(ip)
        return False
    existing.remove(ip)
    _set_alias_ips(uuid, existing)
    blocked_ips.discard(ip)
    print(f"[IPS] ✓ Unblocked {ip} in OPNsense")
    return True

# ─── FORWARD ATTACK TO IPS ────────────────────────────────────────────────────
def forward_to_ips(src_ip, dst_ip, dst_port, proto, attack_type, confidence=0.0):
    """Auto-block attacker IP in OPNsense if confidence >= BLOCK_CONFIDENCE."""
    def _send():
        if confidence >= BLOCK_CONFIDENCE and src_ip not in WHITELIST:
            block_ip(src_ip)
    threading.Thread(target=_send, daemon=True).start()

# ─── ZEEK LOG WATCHER ──────────────────────────────────────────────────────────
def watch_zeek_logs():
    print(f"[*] Watching: {ZEEK_LOG_PATH}")
    state["running"] = True

    while True:
        try:
            if not os.path.exists(ZEEK_LOG_PATH):
                time.sleep(POLL_INTERVAL)
                continue

            with open(ZEEK_LOG_PATH, "r", encoding="utf-8", errors="ignore") as f:
                f.seek(state["zeek_file_pos"])
                new_lines = f.readlines()
                state["zeek_file_pos"] = f.tell()

            for line in new_lines:
                rec = parse_zeek_line(line)
                if rec is None:
                    continue

                label, attack_type, confidence = run_inference(rec)

                src_ip   = rec.get("id.orig_h", "?")
                dst_ip   = rec.get("id.resp_h", "?")
                src_port = rec.get("id.orig_p", "?")
                dst_port = rec.get("id.resp_p", "?")
                proto    = rec.get("proto", "?")
                service  = rec.get("service", "-")
                duration = safe_float(rec.get("duration", "0"))
                orig_bytes = int(safe_float(rec.get("orig_bytes", "0")))
                resp_bytes = int(safe_float(rec.get("resp_bytes", "0")))
                ts       = safe_float(rec.get("ts", str(time.time())))

                conn = {
                    "id":          rec.get("uid", f"uid_{int(ts)}"),
                    "ts":          ts,
                    "time":        datetime.fromtimestamp(ts).strftime("%H:%M:%S"),
                    "src_ip":      src_ip,
                    "dst_ip":      dst_ip,
                    "src_port":    src_port,
                    "dst_port":    dst_port,
                    "proto":       proto,
                    "service":     service if service != "-" else proto,
                    "duration":    round(duration, 3),
                    "orig_bytes":  orig_bytes,
                    "resp_bytes":  resp_bytes,
                    "label":       label,
                    "attack_type": attack_type,
                    "confidence":  confidence,
                }

                with state["lock"]:
                    state["connections"].append(conn)
                    s = state["stats"]
                    s["total"]    += 1
                    s["bytes_in"] += resp_bytes
                    s["bytes_out"]+= orig_bytes
                    s["protocols"][proto] += 1

                    if label == "ATTACK":
                        s["attacks"] += 1
                        s["attack_types"][attack_type] += 1

                        alert = {
                            "id":          f"alert_{int(time.time()*1000)}",
                            "time":        datetime.fromtimestamp(ts).strftime("%H:%M:%S"),
                            "src_ip":      src_ip,
                            "dst_ip":      dst_ip,
                            "proto":       proto,
                            "attack_type": attack_type,
                            "confidence":  confidence,
                            "severity":    "HIGH" if confidence > 85 else ("MEDIUM" if confidence > 60 else "LOW"),
                        }
                        state["alerts"].appendleft(alert)
                        broadcast_sse("alert", alert)
                        forward_to_ips(src_ip, dst_ip, dst_port, proto, attack_type, confidence)
                    else:
                        s["benign"] += 1

                    broadcast_sse("connection", conn)

        except Exception as e:
            print(f"[watcher error] {e}")

        time.sleep(POLL_INTERVAL)

# ─── SSE BROADCASTING ──────────────────────────────────────────────────────────
def broadcast_sse(event_type, data):
    msg = f"event: {event_type}\ndata: {json.dumps(data)}\n\n"
    dead = []
    for q in state["sse_clients"]:
        try:
            q.put_nowait(msg)
        except:
            dead.append(q)
    for q in dead:
        try:
            state["sse_clients"].remove(q)
        except:
            pass

# ─── API ROUTES ────────────────────────────────────────────────────────────────
@app.route("/api/status")
def api_status():
    s = state["stats"]
    with state["lock"]:
        return jsonify({
            "running":     state["running"],
            "total":       s["total"],
            "attacks":     s["attacks"],
            "benign":      s["benign"],
            "bytes_in":    s["bytes_in"],
            "bytes_out":   s["bytes_out"],
            "protocols":   dict(s["protocols"]),
            "attack_types":dict(s["attack_types"]),
            "models_loaded": state["binary_model"] is not None,
        })

@app.route("/api/connections")
def api_connections():
    with state["lock"]:
        conns = list(state["connections"])
    conns.reverse()
    return jsonify(conns[:100])

@app.route("/api/alerts")
def api_alerts():
    with state["lock"]:
        alerts = list(state["alerts"])
    return jsonify(alerts[:50])

@app.route("/api/stream")
def api_stream():
    def generate():
        q = queue.Queue(maxsize=100)
        state["sse_clients"].append(q)
        try:
            yield "data: {\"type\": \"connected\"}\n\n"
            while True:
                try:
                    msg = q.get(timeout=20)
                    yield msg
                except queue.Empty:
                    yield ": heartbeat\n\n"
        except GeneratorExit:
            pass
        finally:
            try:
                state["sse_clients"].remove(q)
            except:
                pass

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Access-Control-Allow-Origin": "*",
        }
    )

@app.route("/api/simulate", methods=["POST"])
def api_simulate():
    import random
    protos   = ["tcp", "udp", "icmp"]
    states   = ["S1", "SF", "REJ", "S0", "RSTO"]
    services = ["http", "dns", "ftp", "smtp", "-"]
    ips      = ["192.168.1.1","10.0.0.5","172.16.0.2","8.8.8.8","1.1.1.1"]

    fake = {
        "ts":         str(time.time()),
        "uid":        f"CSIM{random.randint(1000,9999)}",
        "id.orig_h":  random.choice(ips),
        "id.orig_p":  str(random.randint(1024,65535)),
        "id.resp_h":  random.choice(ips),
        "id.resp_p":  str(random.choice([80,443,22,53,21,25])),
        "proto":      random.choice(protos),
        "service":    random.choice(services),
        "duration":   str(round(random.uniform(0,5),3)),
        "orig_bytes": str(random.randint(0,50000)),
        "resp_bytes": str(random.randint(0,100000)),
        "conn_state": random.choice(states),
        "local_orig": "T",
        "local_resp": "F",
        "missed_bytes":"0",
        "history":    "Sh",
        "orig_pkts":  str(random.randint(1,100)),
        "orig_ip_bytes": str(random.randint(100,60000)),
        "resp_pkts":  str(random.randint(1,100)),
        "resp_ip_bytes": str(random.randint(100,120000)),
        "tunnel_parents": "-",
    }

    label, attack_type, confidence = run_inference(fake)
    ts = float(fake["ts"])
    conn = {
        "id":          fake["uid"],
        "ts":          ts,
        "time":        datetime.fromtimestamp(ts).strftime("%H:%M:%S"),
        "src_ip":      fake["id.orig_h"],
        "dst_ip":      fake["id.resp_h"],
        "src_port":    fake["id.orig_p"],
        "dst_port":    fake["id.resp_p"],
        "proto":       fake["proto"],
        "service":     fake["service"],
        "duration":    round(float(fake["duration"]),3),
        "orig_bytes":  int(fake["orig_bytes"]),
        "resp_bytes":  int(fake["resp_bytes"]),
        "label":       label,
        "attack_type": attack_type,
        "confidence":  confidence,
    }

    with state["lock"]:
        state["connections"].append(conn)
        s = state["stats"]
        s["total"]    += 1
        s["bytes_in"] += conn["resp_bytes"]
        s["bytes_out"]+= conn["orig_bytes"]
        s["protocols"][conn["proto"]] += 1
        if label == "ATTACK":
            s["attacks"] += 1
            s["attack_types"][attack_type] += 1
            alert = {
                "id":          f"alert_{int(time.time()*1000)}",
                "time":        conn["time"],
                "src_ip":      conn["src_ip"],
                "dst_ip":      conn["dst_ip"],
                "proto":       conn["proto"],
                "attack_type": attack_type,
                "confidence":  confidence,
                "severity":    "HIGH" if confidence > 85 else ("MEDIUM" if confidence > 60 else "LOW"),
            }
            state["alerts"].appendleft(alert)
            broadcast_sse("alert", alert)
            forward_to_ips(                                        # ← OPNsense auto-block
                conn["src_ip"], conn["dst_ip"],
                conn["dst_port"], conn["proto"], attack_type, confidence
            )
        else:
            s["benign"] += 1
        broadcast_sse("connection", conn)

    return jsonify({"ok": True, "label": label, "attack_type": attack_type})

@app.route("/api/opnsense/status")
def api_opnsense_status():
    return jsonify({
        "reachable":   opnsense_reachable(),
        "blocked_ips": list(blocked_ips),
    })

@app.route("/api/block/<ip>", methods=["POST"])
def api_block(ip):
    if ip in WHITELIST:
        return jsonify({"ok": False, "reason": "IP is whitelisted"}), 403
    success = block_ip(ip)
    return jsonify({"ok": success, "ip": ip})

@app.route("/api/unblock/<ip>", methods=["POST"])
def api_unblock(ip):
    success = unblock_ip(ip)
    return jsonify({"ok": success, "ip": ip})

# ─── MAIN ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 55)
    print("  IDS Backend Server")
    print("=" * 55)
    load_models()

    watcher_thread = threading.Thread(target=watch_zeek_logs, daemon=True)
    watcher_thread.start()
    print(f"[*] API running at http://localhost:{PORT}")
    print(f"[*] Dashboard:  http://localhost:3000  (open dashboard/index.html)")
    print(f"[*] IPS alerts → http://localhost:5051/api/alert")
    print()

    app.run(host="0.0.0.0", port=PORT, debug=False, threaded=True)