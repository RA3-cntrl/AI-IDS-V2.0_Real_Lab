"""
deployment.py  (LIVE VERSION)
==============================
Upgraded version of your original deployment.py.

NEW: Instead of reading a static CSV once, this version watches
     the CSV file written by zeek_to_csv.py in real-time and
     runs the AI models on every new batch of rows as they arrive.

How it works:
    zeek_to_csv.py  →  extra_cleaned_ids_dataset.csv  →  this script

How to run:
    1. Start Zeek:          sudo zeek -i eth0
    2. Start converter:     python zeek_to_csv.py
    3. Start IDS:           python deployment.py

What it needs in the same folder:
    - ids_binary_model.pkl
    - ids_multiclass_model.pkl
    - extra_cleaned_ids_dataset.csv   (written live by zeek_to_csv.py)

Original features preserved:
    - Same FEATURES list
    - Same confidence threshold logic
    - Same proto / dest_port decode for human-readable alerts
    - Same alert log format
"""

# ============================================================
# IMPORTS
# ============================================================

import pickle
import pandas as pd
import numpy as np
import os
import time
from datetime import datetime


# ============================================================
# STEP 1 — SETTINGS
# ============================================================

FEATURES = [
    "duration",
    "orig_ip_bytes",
    "resp_ip_bytes",
    "proto",
    "dest_port_zeek",
    "conn_state",
    "history",
    "orig_pkts",
]

BINARY_MODEL_FILE     = "ids_binary_model.pkl"
MULTICLASS_MODEL_FILE = "ids_multiclass_model.pkl"
DATA_FILE             = "extra_cleaned_ids_dataset.csv"
ALERT_LOG_FILE        = "ids_alert_log.txt"

# Set to None to run forever in live mode
TEST_ROWS = None

# Confidence threshold
CONFIDENCE_THRESHOLD = 0.6

# How often to check for new rows in live mode (seconds)
LIVE_POLL_INTERVAL = 3

# ── Reverse lookup for proto (same logic as original) ─────────────────────
PROTO_LOOKUP = {
    round(0.0, 4): "icmp",
    round(1/3, 4): "tcp",
    round(2/3, 4): "udp",
    round(1.0, 4): "unknown",
}

DEST_PORT_MIN = 0
DEST_PORT_MAX = 65535

def decode_proto(scaled_value):
    key = round(float(scaled_value), 4)
    return PROTO_LOOKUP.get(key, f"proto({scaled_value:.4f})")

def decode_dest_port(scaled_value):
    original = round(float(scaled_value) * (DEST_PORT_MAX - DEST_PORT_MIN) + DEST_PORT_MIN)
    return str(original)


# ============================================================
# STEP 2 — LOAD THE TRAINED MODELS
# ============================================================

def load_models():
    print("\n" + "=" * 55)
    print("  AI-IDS/IPS — Intrusion Detection System (LIVE)")
    print("=" * 55)
    print("\nLoading trained models...")

    for model_file in [BINARY_MODEL_FILE, MULTICLASS_MODEL_FILE]:
        if not os.path.exists(model_file):
            print(f"\n  ERROR: Model file not found — {model_file}")
            print("  Make sure you ran the training script first.")
            exit()

    with open(BINARY_MODEL_FILE, "rb") as f:
        binary_model = pickle.load(f)
    print(f"  Binary model loaded       ✓  ({BINARY_MODEL_FILE})")

    with open(MULTICLASS_MODEL_FILE, "rb") as f:
        multiclass_model = pickle.load(f)
    print(f"  Multi-class model loaded  ✓  ({MULTICLASS_MODEL_FILE})")

    return binary_model, multiclass_model


# ============================================================
# STEP 3 — PROCESS A BATCH OF ROWS
# ============================================================

def process_batch(binary_model, multiclass_model, batch_df, log, alert_counter, total_counts):
    """
    Run models on a DataFrame batch.
    Returns updated alert_counter and total_counts dict.
    """
    for i in range(len(batch_df)):
        row = batch_df.iloc[[i]]
        total_counts["checked"] += 1

        # Ensure all features exist and are numeric
        X = row[FEATURES].copy()
        for col in FEATURES:
            X[col] = pd.to_numeric(X[col], errors="coerce").fillna(0)

        # ---- BINARY MODEL ----
        probabilities     = binary_model.predict_proba(X)[0]
        attack_confidence = probabilities[1]

        if attack_confidence < CONFIDENCE_THRESHOLD:
            total_counts["benign"] += 1
            continue

        # ---- MULTI-CLASS MODEL ----
        try:
            attack_type = multiclass_model.predict(X)[0]
        except Exception:
            attack_type = "Unknown"

        # ---- BUILD ALERT ----
        alert_counter += 1
        timestamp      = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        confidence_pct = round(attack_confidence * 100, 1)

        proto     = decode_proto(X["proto"].iloc[0])
        dest_port = decode_dest_port(X["dest_port_zeek"].iloc[0])
        duration  = X["duration"].iloc[0]

        alert_line = (
            f"[ALERT #{alert_counter}]\n"
            f"  Time        : {timestamp}\n"
            f"  Confidence  : {confidence_pct}% sure this is an attack\n"
            f"  Attack Type : {attack_type}\n"
            f"  Protocol    : {proto}\n"
            f"  Dest Port   : {dest_port}\n"
            f"  Duration    : {duration}s\n"
            f"  Row Index   : {total_counts['checked']}\n"
        )

        print(f"\n  🚨 {alert_line}")
        log.write(alert_line + "\n")
        total_counts["alerts"] += 1

        time.sleep(0.005)

    return alert_counter, total_counts


# ============================================================
# STEP 4 — LIVE MODE: watch CSV and process new rows
# ============================================================

def run_live(binary_model, multiclass_model):
    print("\n" + "-" * 55)
    print("  LIVE MODE — watching for new connections...")
    print(f"  Reading from : {DATA_FILE}")
    print(f"  Poll interval: {LIVE_POLL_INTERVAL}s")
    print("-" * 55)

    last_row_count = 0
    alert_counter  = 0
    total_counts   = {"checked": 0, "benign": 0, "alerts": 0}

    with open(ALERT_LOG_FILE, "w") as log:
        log.write("AI-IDS/IPS Alert Log — LIVE MODE\n")
        log.write(f"Scan started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        log.write("=" * 55 + "\n\n")

        print(f"\n[{datetime.now().strftime('%H:%M:%S')}] Waiting for data in {DATA_FILE} ...")

        while True:
            try:
                # Wait for file to exist
                if not os.path.exists(DATA_FILE):
                    time.sleep(LIVE_POLL_INTERVAL)
                    continue

                df = pd.read_csv(DATA_FILE, low_memory=False)
                current_row_count = len(df)

                if current_row_count > last_row_count:
                    new_rows = df.iloc[last_row_count:current_row_count].copy()
                    print(f"\n[{datetime.now().strftime('%H:%M:%S')}] "
                          f"{len(new_rows)} new connection(s) — scanning...")

                    alert_counter, total_counts = process_batch(
                        binary_model, multiclass_model,
                        new_rows, log, alert_counter, total_counts
                    )

                    last_row_count = current_row_count
                    print(f"  Checked: {total_counts['checked']} | "
                          f"Benign: {total_counts['benign']} | "
                          f"Alerts: {total_counts['alerts']}")

                else:
                    print(f"[{datetime.now().strftime('%H:%M:%S')}] "
                          f"No new rows. Total checked: {total_counts['checked']}", end="\r")

            except KeyboardInterrupt:
                print("\n\n[!] IDS stopped by user.")
                break
            except Exception as e:
                print(f"\n[ERROR] {e}")

            time.sleep(LIVE_POLL_INTERVAL)

    return total_counts["checked"], total_counts["alerts"], total_counts["benign"]


# ============================================================
# STEP 5 — STATIC MODE: run once on existing CSV (original)
# ============================================================

def run_static(binary_model, multiclass_model):
    """Original behaviour — read full CSV and scan once."""
    print(f"\nLoading static data from {DATA_FILE}...")

    if not os.path.exists(DATA_FILE):
        print(f"\n  ERROR: Data file not found — {DATA_FILE}")
        exit()

    df = pd.read_csv(DATA_FILE, low_memory=False)
    print(f"  Total rows available : {len(df):,}")

    if TEST_ROWS is not None:
        df = df.head(TEST_ROWS)
        print(f"  Using first {TEST_ROWS:,} rows")

    for col in FEATURES:
        if col not in df.columns:
            print(f"  WARNING: Feature '{col}' missing — filling with 0")
            df[col] = 0

    X = df[FEATURES].copy()
    for col in FEATURES:
        X[col] = pd.to_numeric(X[col], errors="coerce").fillna(0)

    print("\n" + "-" * 55)
    print("  Starting IDS scan (static mode)...")
    print("-" * 55)

    total_checked = 0
    total_alerts  = 0
    total_benign  = 0
    alert_counter = 0

    with open(ALERT_LOG_FILE, "w") as log:
        log.write("AI-IDS/IPS Alert Log — STATIC MODE\n")
        log.write(f"Scan started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        log.write("=" * 55 + "\n\n")

        dummy_counts = {"checked": 0, "benign": 0, "alerts": 0}
        alert_counter, dummy_counts = process_batch(
            binary_model, multiclass_model, df, log, alert_counter, dummy_counts
        )
        total_checked = dummy_counts["checked"]
        total_alerts  = dummy_counts["alerts"]
        total_benign  = dummy_counts["benign"]

        summary = (
            f"\n{'=' * 55}\n"
            f"SCAN SUMMARY\n"
            f"{'=' * 55}\n"
            f"  Total connections checked : {total_checked:,}\n"
            f"  Benign (no alert)         : {total_benign:,}\n"
            f"  Alerts raised             : {total_alerts:,}\n"
            f"  Scan finished             : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        )
        log.write(summary)

    return total_checked, total_alerts, total_benign


# ============================================================
# STEP 6 — PRINT FINAL SUMMARY
# ============================================================

def print_summary(total_checked, total_alerts, total_benign):
    alert_rate = round((total_alerts / total_checked) * 100, 2) if total_checked > 0 else 0

    print("\n" + "=" * 55)
    print("  SCAN COMPLETE")
    print("=" * 55)
    print(f"  Total connections checked : {total_checked:,}")
    print(f"  Benign (safe, no alert)   : {total_benign:,}")
    print(f"  Alerts raised             : {total_alerts:,}")
    print(f"  Alert rate                : {alert_rate}%")
    print(f"\n  Full alert log saved to   : {ALERT_LOG_FILE}")
    print("=" * 55 + "\n")

    if total_alerts == 0:
        print("  ✅ No attacks detected.")
    else:
        print(f"  ⚠️  {total_alerts} suspicious connections flagged.")
        print("  Review the alert log for details.")


# ============================================================
# MAIN — choose live or static mode
# ============================================================

if __name__ == "__main__":

    binary_model, multiclass_model = load_models()

    print("\n  Run mode:")
    print("    [1] LIVE   — watch CSV updated by zeek_to_csv.py in real-time")
    print("    [2] STATIC — scan existing CSV once (original behaviour)")
    mode = input("\n  Enter 1 or 2: ").strip()

    if mode == "1":
        total_checked, total_alerts, total_benign = run_live(binary_model, multiclass_model)
    else:
        total_checked, total_alerts, total_benign = run_static(binary_model, multiclass_model)

    print_summary(total_checked, total_alerts, total_benign)
