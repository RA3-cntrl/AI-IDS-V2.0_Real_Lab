"""
AI-IDS Backend — Single-file, binary-only, step-by-step console output
=======================================================================
Architecture:
  Ubuntu (192.168.151.135) ←ens33← network traffic
  Zeek writes /opt/zeek/logs/current/conn.log
  This script tails that file, encodes each row exactly as the RF was
  trained (encoding lifted verbatim from deployment.py / step3b),
  predicts ATTACK / BENIGN, blocks attacker via OPNsense API, streams
  events to dashboard.html over SSE.

Run from the folder that contains your .pkl and .json files:
    cd ~/pfe_files/AI-IDS-main
    python3 backend.py

Dependencies:
    pip3 install flask flask-cors scikit-learn pandas numpy requests urllib3
"""

import os, json, time, pickle, threading, queue, math, requests, urllib3
from datetime import datetime
from collections import deque, defaultdict
from flask import Flask, jsonify, Response, stream_with_context, send_from_directory
from flask_cors import CORS
import pandas as pd
import numpy as np

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ══════════════════════════════════════════════════════════════════════════════
#  CONFIG  — edit these paths if your layout differs
# ══════════════════════════════════════════════════════════════════════════════
ZEEK_LOG_PATH       = "/opt/zeek/logs/current/conn.log"   # live Zeek log
BINARY_MODEL_PATH   = "ids_binary_model.pkl"              # Random Forest binary
ENCODER_PATH        = "encoder_mappings.json"             # from step3b
DASHBOARD_DIR       = "."                                  # folder with dashboard.html
POLL_INTERVAL       = 1.5          # seconds between tail reads
MAX_HISTORY         = 500
MAX_ALERTS          = 200
PORT                = 5050

# ── OPNsense IPS ──────────────────────────────────────────────────────────────
OPNSENSE_HOST    = "https://192.168.151.129"   # LAN IP of your OPNsense
OPNSENSE_API_KEY = "PASTE_YOUR_API_KEY_HERE"
OPNSENSE_API_SEC = "PASTE_YOUR_API_SECRET_HERE"
ALIAS_NAME       = "IDS_Blocklist"
BLOCK_CONFIDENCE = 90.0   # auto-block only when confidence >= 90 %

WHITELIST = {
    "192.168.151.1",
    "127.0.0.1",
    "192.168.151.129",   # OPNsense — never block the gateway
    "192.168.151.135",   # this server — never block yourself
    "8.8.8.8", "8.8.4.4",
}

# ══════════════════════════════════════════════════════════════════════════════
#  FEATURE COLUMNS — must match your training exactly (from step3b)
# ══════════════════════════════════════════════════════════════════════════════
FEATURE_COLS = [
    "duration", "orig_ip_bytes", "resp_ip_bytes", "proto",
    "dest_port_zeek", "conn_state", "history", "orig_pkts"
]
CATEGORICAL_COLS = ["proto", "conn_state", "history"]

# ── Zeek conn.log field order (TSV header) ────────────────────────────────────
ZEEK_FIELDS = [
    "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
    "proto", "service", "duration", "orig_bytes", "resp_bytes",
    "conn_state", "local_orig", "local_resp", "missed_bytes",
    "history", "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes",
    "tunnel_parents"
]

# ── Categorical encoding maps (same dicts your step3b wrote) ──────────────────
PROTO_MAP = {"icmp": "0", "tcp": "1", "udp": "2"}
CONN_STATE_MAP = {
    "S0": "0", "S1": "1", "SF": "2", "REJ": "3",
    "S2": "4", "S3": "5", "RSTO": "6", "RSTR": "5",
    "RSTOS0": "4", "OTH": "3", "SH": "1", "SHR": "2"
}

# ══════════════════════════════════════════════════════════════════════════════
#  APP + GLOBAL STATE
# ══════════════════════════════════════════════════════════════════════════════
app = Flask(__name__, static_folder=DASHBOARD_DIR)
CORS(app)

state = {
    "connections":  deque(maxlen=MAX_HISTORY),
    "alerts":       deque(maxlen=MAX_ALERTS),
    "stats": {
        "total": 0, "attacks": 0, "benign": 0,
        "bytes_in": 0, "bytes_out": 0,
        "protocols": defaultdict(int),
        "attack_types": defaultdict(int),
    },
    "sse_clients":  [],
    "lock":         threading.Lock(),
    "binary_model": None,
    "encoders":     {},
    "zeek_file_pos": 0,
    "running":      False,
    "blocked_ips":  set(),
}

# ══════════════════════════════════════════════════════════════════════════════
#  STEP 1 — MODEL + ENCODER LOADING  (verbose)
# ══════════════════════════════════════════════════════════════════════════════
def load_models():
    print("\n" + "═"*55)
    print("  STEP 1 — Loading models & encoders")
    print("═"*55)

    # Binary model
    try:
        with open(BINARY_MODEL_PATH, "rb") as f:
            state["binary_model"] = pickle.load(f)
        print(f"  [✓] Binary model loaded  : {BINARY_MODEL_PATH}")
        print(f"      Type                 : {type(state['binary_model']).__name__}")
    except FileNotFoundError:
        print(f"  [✗] {BINARY_MODEL_PATH} not found — running in DEMO mode (random labels)")
    except Exception as e:
        print(f"  [✗] Binary model error   : {e}")

    # Encoder mappings (produced by step3b)
    try:
        with open(ENCODER_PATH, "r") as f:
            state["encoders"] = json.load(f)
        print(f"  [✓] Encoders loaded      : {ENCODER_PATH}")
        for col, mapping in state["encoders"].items():
            print(f"      {col:12s}        : {mapping}")
    except FileNotFoundError:
        print(f"  [✗] {ENCODER_PATH} not found — categorical features will use fallback maps")
    except Exception as e:
        print(f"  [✗] Encoder error        : {e}")

    print("═"*55 + "\n")

# ══════════════════════════════════════════════════════════════════════════════
#  STEP 2 — ZEEK LINE PARSING  (verbose)
# ══════════════════════════════════════════════════════════════════════════════
def safe_float(val, default=0.0):
    try:
        return default if val in ("-", "", None) else float(val)
    except Exception:
        return default

def parse_zeek_line(line: str) -> dict | None:
    """Parse JSON (new Zeek) or TSV (classic Zeek) conn.log line."""
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    if line.startswith("{"):
        try:
            j = json.loads(line)
            return {
                "ts":            str(j.get("ts","")),
                "uid":           j.get("uid","-"),
                "id.orig_h":     j.get("id.orig_h","-"),
                "id.orig_p":     str(j.get("id.orig_p","0")),
                "id.resp_h":     j.get("id.resp_h","-"),
                "id.resp_p":     str(j.get("id.resp_p","0")),
                "proto":         j.get("proto","-"),
                "service":       j.get("service","-"),
                "duration":      str(j.get("duration","0")),
                "orig_bytes":    str(j.get("orig_bytes","0")),
                "resp_bytes":    str(j.get("resp_bytes","0")),
                "conn_state":    j.get("conn_state","-"),
                "local_orig":    str(j.get("local_orig","-")),
                "local_resp":    str(j.get("local_resp","-")),
                "missed_bytes":  str(j.get("missed_bytes","0")),
                "history":       j.get("history","-"),
                "orig_pkts":     str(j.get("orig_pkts","0")),
                "orig_ip_bytes": str(j.get("orig_ip_bytes","0")),
                "resp_pkts":     str(j.get("resp_pkts","0")),
                "resp_ip_bytes": str(j.get("resp_ip_bytes","0")),
            }
        except:
            return None
    parts = line.split("\t")
    if len(parts) < 15:
        return None
    return {f:(parts[i] if i<len(parts) else "-") for i,f in enumerate(ZEEK_FIELDS)}

# ══════════════════════════════════════════════════════════════════════════════
#  STEP 3 — FEATURE ENCODING  (exact replica of your deployment.py logic)
# ══════════════════════════════════════════════════════════════════════════════
def _minmax(val, mn, mx):
    rng = mx - mn
    if rng == 0: return 0.0
    return max(0.0, min(1.0, (val - mn) / rng))

def encode_features(rec: dict) -> pd.DataFrame:
    enc = state["encoders"]
    ns  = enc.get("numeric_scalers", {})
    hv  = enc.get("history_values",  {})
    pm  = enc.get("proto",           {})
    cm  = enc.get("conn_state",      {})
    proto_enc = float(pm.get(PROTO_MAP.get(rec.get("proto","-").lower(), "3"), "0.0"))
    conn_enc  = float(cm.get(CONN_STATE_MAP.get(rec.get("conn_state","-"), "0"), "0.0"))
    hist_enc  = float(hv.get(rec.get("history","-"), hv.get("-","0.0")))
    dur_enc = _minmax(safe_float(rec.get("duration","0")),      ns.get("duration",{}).get("min",0.0),      ns.get("duration",{}).get("max",221.54))
    ob_enc  = _minmax(safe_float(rec.get("orig_ip_bytes","0")), ns.get("orig_ip_bytes",{}).get("min",40.0),  ns.get("orig_ip_bytes",{}).get("max",111792.0))
    rb_enc  = _minmax(safe_float(rec.get("resp_ip_bytes","0")), ns.get("resp_ip_bytes",{}).get("min",0.0),   ns.get("resp_ip_bytes",{}).get("max",346828.0))
    dp_enc  = _minmax(safe_float(rec.get("id.resp_p","0")),     ns.get("dest_port_zeek",{}).get("min",0.0),  ns.get("dest_port_zeek",{}).get("max",5355.0))
    pk_enc  = _minmax(safe_float(rec.get("orig_pkts","0")),     ns.get("orig_pkts",{}).get("min",1.0),       ns.get("orig_pkts",{}).get("max",296.0))
    return pd.DataFrame([{
        "duration": dur_enc, "orig_ip_bytes": ob_enc, "resp_ip_bytes": rb_enc,
        "proto": proto_enc, "dest_port_zeek": dp_enc,
        "conn_state": conn_enc, "history": hist_enc, "orig_pkts": pk_enc,
    }])[FEATURE_COLS]
# ══════════════════════════════════════════════════════════════════════════════
#  STEP 4 — INFERENCE  (verbose console output per connection)
# ══════════════════════════════════════════════════════════════════════════════
def run_inference(rec: dict) -> tuple[str, float]:
    """Returns (label, confidence_pct).  label = 'ATTACK' | 'NORMAL'."""
    binary_model = state["binary_model"]

    # ── Print raw Zeek values ────────────────────────────────────────────────
    src = rec.get("id.orig_h", "?")
    dst = rec.get("id.resp_h", "?")
    proto  = rec.get("proto", "?")
    dport  = rec.get("id.resp_p", "?")
    dur    = rec.get("duration", "-")
    obytes = rec.get("orig_ip_bytes", "-")
    rbytes = rec.get("resp_ip_bytes", "-")
    cstate = rec.get("conn_state", "-")
    hist   = rec.get("history", "-")
    pkts   = rec.get("orig_pkts", "-")

    print(f"\n{'─'*55}")
    print(f"  [STEP 2] New Zeek connection")
    print(f"  {'src':>12} : {src}:{rec.get('id.orig_p','?')}")
    print(f"  {'dst':>12} : {dst}:{dport}")
    print(f"  {'proto':>12} : {proto}   conn_state: {cstate}")
    print(f"  {'duration':>12} : {dur}s   orig_pkts: {pkts}")
    print(f"  {'orig_bytes':>12} : {obytes}   resp_bytes: {rbytes}")
    print(f"  {'history':>12} : {hist}")

    # ── Encode ───────────────────────────────────────────────────────────────
    features = encode_features(rec)
    print(f"\n  [STEP 3] Encoded feature vector:")
    for col in FEATURE_COLS:
        print(f"  {'':>4}{col:20s} = {features[col].values[0]:.6f}")

    # ── Predict ──────────────────────────────────────────────────────────────
    if binary_model is None:
        import random
        label = "ATTACK" if random.random() < 0.3 else "NORMAL"
        confidence = round(random.uniform(55, 99), 1)
        print(f"\n  [STEP 4] DEMO mode (no model)  → {label}  ({confidence}%)")
        return label, confidence

    try:
        pred  = binary_model.predict(features)[0]
        label = "NORMAL" if str(pred) in ("0", "0.0", "BENIGN", "NORMAL") else "ATTACK"

        try:
            proba      = binary_model.predict_proba(features)[0]
            confidence = round(float(max(proba)) * 100, 1)
        except Exception:
            confidence = 0.0

        # ── Confidence threshold — ignore weak predictions ──────────────
        if label == "ATTACK" and confidence < 70.0:
            label = "NORMAL"
            print(f"\n  [STEP 4] Low confidence ({confidence}%) → downgraded to NORMAL")

        severity = "HIGH" if confidence > 85 else ("MEDIUM" if confidence > 60 else "LOW")
        flag = "🚨 ATTACK" if label == "ATTACK" else "✅ NORMAL"
        print(f"\n  [STEP 4] Prediction → {flag}  confidence={confidence}%  severity={severity}")
        return label, confidence

    except Exception as e:
        print(f"\n  [STEP 4] Inference error: {e}")
        return "ERROR", 0.0

# ══════════════════════════════════════════════════════════════════════════════
#  OPNSENSE IPS HELPERS
# ══════════════════════════════════════════════════════════════════════════════
def _opns(method, path, payload=None):
    url = f"{OPNSENSE_HOST}/api/{path}"
    try:
        r = requests.request(method, url,
                             auth=(OPNSENSE_API_KEY, OPNSENSE_API_SEC),
                             json=payload, verify=False, timeout=5)
        return r.json()
    except Exception as e:
        print(f"  [OPNsense] API error: {e}")
        return None

def _alias_uuid():
    r = _opns("GET", f"firewall/alias/getAliasUUID/{ALIAS_NAME}")
    if r:
        uuid = r.get("uuid", "")
        if uuid:
            return uuid
    r2 = _opns("GET", "firewall/alias/searchItem")
    if r2:
        for row in r2.get("rows", []):
            if row.get("name") == ALIAS_NAME:
                return row.get("uuid", "")
    return None

def _alias_ips(uuid):
    data = _opns("GET", f"firewall/alias/getAlias/{uuid}")
    if not data:
        return []
    content = data.get("alias", {}).get("content", {})
    if isinstance(content, dict):
        return [v.get("value", "") for v in content.values() if v.get("value")]
    return []

def _alias_set(uuid, ip_list):
    payload = {"alias": {
        "name": ALIAS_NAME, "type": "host", "proto": "",
        "counters": "0", "enabled": "1",
        "description": "IDS auto-blocklist",
        "content": "\n".join(ip_list),
    }}
    _opns("POST", f"firewall/alias/setItem/{uuid}", payload)
    _opns("POST", "firewall/alias/reconfigure", {})

def block_ip(ip: str) -> bool:
    if ip in WHITELIST or ip in state["blocked_ips"]:
        return False
    print(f"\n  [STEP 5] 🔒 Blocking {ip} in OPNsense...")
    uuid = _alias_uuid()
    if not uuid:
        print(f"  [IPS] ✗ Cannot find alias '{ALIAS_NAME}' — create it in OPNsense first")
        return False
    existing = _alias_ips(uuid)
    if ip not in existing:
        existing.append(ip)
        _alias_set(uuid, existing)
    state["blocked_ips"].add(ip)
    print(f"  [IPS] ✓ {ip} added to {ALIAS_NAME} and firewall reconfigured")
    return True

def maybe_block(src_ip, confidence):
    """Block in background thread — never stalls the watcher."""
    if confidence >= BLOCK_CONFIDENCE and src_ip not in WHITELIST:
        threading.Thread(target=block_ip, args=(src_ip,), daemon=True).start()

# ══════════════════════════════════════════════════════════════════════════════
#  STEP 5 — SSE BROADCAST
# ══════════════════════════════════════════════════════════════════════════════
def broadcast(event_type: str, data: dict):
    msg  = f"event: {event_type}\ndata: {json.dumps(data)}\n\n"
    dead = []
    for q in state["sse_clients"]:
        try:
            q.put_nowait(msg)
        except Exception:
            dead.append(q)
    for q in dead:
        try: state["sse_clients"].remove(q)
        except Exception: pass

# ══════════════════════════════════════════════════════════════════════════════
#  ZEEK LOG WATCHER THREAD
# ══════════════════════════════════════════════════════════════════════════════
def watch_zeek():
    print(f"\n{'═'*55}")
    print(f"  STEP 2 — Zeek watcher started")
    print(f"  Watching : {ZEEK_LOG_PATH}")
    print(f"  Poll     : every {POLL_INTERVAL}s")
    print(f"{'═'*55}\n")
    state["running"] = True

    while True:
        try:
            if not os.path.exists(ZEEK_LOG_PATH):
                print(f"  [watcher] Waiting for {ZEEK_LOG_PATH} ...")
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
                if rec.get("id.resp_p","") == "5050":
                    continue

                label, confidence = run_inference(rec)

                ts         = safe_float(rec.get("ts", str(time.time())))
                src_ip     = rec.get("id.orig_h", "?")
                dst_ip     = rec.get("id.resp_h", "?")
                proto      = rec.get("proto", "?")
                service    = rec.get("service", "-")
                orig_bytes = int(safe_float(rec.get("orig_bytes", "0")))
                resp_bytes = int(safe_float(rec.get("resp_bytes", "0")))
                severity   = ("HIGH" if confidence > 85
                              else "MEDIUM" if confidence > 60 else "LOW")

                conn = {
                    "id":         rec.get("uid", f"uid_{int(ts)}"),
                    "ts":         ts,
                    "time":       datetime.fromtimestamp(ts).strftime("%H:%M:%S"),
                    "src_ip":     src_ip,
                    "dst_ip":     dst_ip,
                    "src_port":   rec.get("id.orig_p", "?"),
                    "dst_port":   rec.get("id.resp_p", "?"),
                    "proto":      proto,
                    "service":    service if service != "-" else proto,
                    "duration":   round(safe_float(rec.get("duration", "0")), 3),
                    "orig_bytes": orig_bytes,
                    "resp_bytes": resp_bytes,
                    "label":      label,
                    "confidence": confidence,
                    "severity":   severity,
                }

                with state["lock"]:
                    state["connections"].append(conn)
                    s = state["stats"]
                    s["total"]     += 1
                    s["bytes_in"]  += resp_bytes
                    s["bytes_out"] += orig_bytes
                    s["protocols"][proto] += 1

                    if label == "ATTACK":
                        s["attacks"] += 1

                        alert = {
                            "id":         f"alert_{int(time.time()*1000)}",
                            "time":       conn["time"],
                            "src_ip":     src_ip,
                            "dst_ip":     dst_ip,
                            "dst_port":   conn["dst_port"],
                            "proto":      proto,
                            "confidence": confidence,
                            "severity":   severity,
                        }
                        state["alerts"].appendleft(alert)
                        broadcast("alert", alert)
                        print(f"\n  [STEP 5] Alert broadcast → {src_ip} → {dst_ip}:{conn['dst_port']}")
                        maybe_block(src_ip, confidence)

                    else:
                        s["benign"] += 1

                    broadcast("connection", conn)

        except Exception as e:
            print(f"  [watcher error] {e}")

        time.sleep(POLL_INTERVAL)

# ══════════════════════════════════════════════════════════════════════════════
#  API ROUTES
# ══════════════════════════════════════════════════════════════════════════════
@app.route("/")
def serve_dashboard():
    return send_from_directory(DASHBOARD_DIR, "dashboard.html")

@app.route("/api/status")
def api_status():
    s = state["stats"]
    with state["lock"]:
        return jsonify({
            "running":       state["running"],
            "total":         s["total"],
            "attacks":       s["attacks"],
            "benign":        s["benign"],
            "bytes_in":      s["bytes_in"],
            "bytes_out":     s["bytes_out"],
            "protocols":     dict(s["protocols"]),
            "models_loaded": state["binary_model"] is not None,
            "blocked_ips":   list(state["blocked_ips"]),
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
        return jsonify(list(state["alerts"])[:50])

@app.route("/api/stream")
def api_stream():
    """Server-Sent Events endpoint — dashboard subscribes here."""
    def generate():
        q = queue.Queue(maxsize=100)
        state["sse_clients"].append(q)
        try:
            yield 'data: {"type":"connected"}\n\n'
            while True:
                try:
                    yield q.get(timeout=20)
                except queue.Empty:
                    yield ": heartbeat\n\n"
        except GeneratorExit:
            pass
        finally:
            try: state["sse_clients"].remove(q)
            except Exception: pass

    return Response(stream_with_context(generate()),
                    mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache",
                             "X-Accel-Buffering": "no",
                             "Access-Control-Allow-Origin": "*"})

@app.route("/api/simulate", methods=["POST"])
def api_simulate():
    """Inject a fake Zeek record — useful while waiting for real traffic."""
    import random
    fake = {
        "ts":          str(time.time()),
        "uid":         f"SIM{random.randint(1000,9999)}",
        "id.orig_h":   random.choice(["10.0.0.5","172.16.0.2","203.0.113.1","198.51.100.4"]),
        "id.orig_p":   str(random.randint(1024, 65535)),
        "id.resp_h":   "192.168.151.135",
        "id.resp_p":   str(random.choice([80, 443, 22, 53, 21, 8080])),
        "proto":       random.choice(["tcp", "udp", "icmp"]),
        "service":     random.choice(["http","dns","ssh","-"]),
        "duration":    str(round(random.uniform(0, 5), 3)),
        "orig_bytes":  str(random.randint(0, 50000)),
        "resp_bytes":  str(random.randint(0, 100000)),
        "conn_state":  random.choice(["S0","S1","SF","REJ","RSTO"]),
        "local_orig":  "T", "local_resp": "F", "missed_bytes": "0",
        "history":     random.choice(["Sh","ShA","D","S","d"]),
        "orig_pkts":   str(random.randint(1, 200)),
        "orig_ip_bytes": str(random.randint(100, 60000)),
        "resp_pkts":   str(random.randint(1, 200)),
        "resp_ip_bytes": str(random.randint(100, 120000)),
        "tunnel_parents": "-",
    }
    label, confidence = run_inference(fake)
    return jsonify({"ok": True, "label": label, "confidence": confidence})

@app.route("/api/block/<ip>", methods=["POST"])
def api_block(ip):
    if ip in WHITELIST:
        return jsonify({"ok": False, "reason": "whitelisted"}), 403
    return jsonify({"ok": block_ip(ip), "ip": ip})

@app.route("/api/unblock/<ip>", methods=["POST"])
def api_unblock(ip):
    uuid = _alias_uuid()
    if not uuid:
        return jsonify({"ok": False, "reason": "alias not found"}), 500
    ips = _alias_ips(uuid)
    if ip in ips:
        ips.remove(ip)
        _alias_set(uuid, ips)
    state["blocked_ips"].discard(ip)
    return jsonify({"ok": True, "ip": ip})

# ══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    print("═"*55)
    print("  AI-IDS Backend — Step-by-Step Mode")
    print("  Ubuntu sensor  : 192.168.151.135")
    print("  OPNsense GW    : 192.168.151.129")
    print("═"*55)

    # STEP 1 — load models
    load_models()

    # STEP 2 — start Zeek watcher thread
    threading.Thread(target=watch_zeek, daemon=True).start()

    print(f"  Dashboard → http://192.168.151.135:{PORT}/")
    print(f"  API       → http://192.168.151.135:{PORT}/api/status")
    print(f"  Simulate  → POST http://192.168.151.135:{PORT}/api/simulate")
    print("═"*55 + "\n")

    app.run(host="0.0.0.0", port=PORT, debug=False, threaded=True)
