#!/usr/bin/env python3
"""
IDS Label & Retrain Tool
-------------------------
Run this after any attack test.
It reads recent captured traffic, asks you to label it,
appends it to your dataset, and optionally retrains the model.

Usage:
    python3 label_and_retrain.py
"""

import os
import subprocess
import pandas as pd
from datetime import datetime

# ─────────────────────────────────────────────
# CONFIG — change these paths if needed
# ─────────────────────────────────────────────
DATASET_PATH    = "/home/kali/IDS/extra_cleaned_ids_dataset.csv"
TRAINING_SCRIPT = "/home/kali/IDS/training_randomforest.py"
LIVE_CSV        = "/home/kali/IDS/live_traffic.csv"   # zeek_to_csv output
RETRAIN_AFTER   = 10   # auto-ask to retrain after this many new entries
LOG_FILE        = "/home/kali/IDS/labeled_log.txt"
# ─────────────────────────────────────────────

LABELS = [
    "Reconnaissance",
    "Credential Access",
    "Defense Evasion",
    "Lateral Movement",
    "Execution",
    "Persistence",
    "Exfiltration",
    "none"
]

SEPARATOR = "─" * 60


def banner():
    print("\n" + SEPARATOR)
    print("   IDS LABEL & RETRAIN TOOL")
    print(SEPARATOR)


def pick_label():
    print("\nWhat was this traffic actually?\n")
    for i, label in enumerate(LABELS, 1):
        print(f"  [{i}] {label}")
    print("  [s] Skip this entry")
    print("  [q] Quit\n")

    while True:
        choice = input("Your choice: ").strip().lower()
        if choice == "q":
            return None
        if choice == "s":
            return "skip"
        if choice.isdigit() and 1 <= int(choice) <= len(LABELS):
            return LABELS[int(choice) - 1]
        print("  Invalid — enter a number, 's' to skip, or 'q' to quit.")


def show_entry(row, index, total):
    print(f"\n{SEPARATOR}")
    print(f"  Entry {index} of {total}")
    print(SEPARATOR)
    fields = [
        "proto", "dest_port_zeek", "duration",
        "orig_ip_bytes", "resp_ip_bytes",
        "orig_pkts", "resp_pkts",
        "conn_state", "history"
    ]
    for f in fields:
        if f in row:
            print(f"  {f:<20} {row[f]}")
    print()


def load_live_traffic():
    if not os.path.exists(LIVE_CSV):
        print(f"\n[!] Live traffic file not found: {LIVE_CSV}")
        print("    Make sure Zeek is running and has captured some traffic.")
        return None

    df = pd.read_csv(LIVE_CSV)

    if df.empty:
        print("\n[!] Live traffic file is empty. Run an attack first.")
        return None

    # Only show rows not already labeled (label == "none" or unlabeled)
    if "label_tactic" in df.columns:
        unlabeled = df[df["label_tactic"].isin(["none", "", "unknown"])].copy()
    else:
        unlabeled = df.copy()

    if unlabeled.empty:
        print("\n[!] No unlabeled traffic found in live_traffic.csv.")
        return None

    print(f"\n[+] Found {len(unlabeled)} unlabeled entries in live traffic.")
    return unlabeled


def append_to_dataset(rows):
    if not rows:
        return 0

    new_df = pd.DataFrame(rows)

    if os.path.exists(DATASET_PATH):
        existing = pd.read_csv(DATASET_PATH, nrows=1)
        new_df = new_df.reindex(columns=existing.columns, fill_value=0)
        new_df.to_csv(DATASET_PATH, mode="a", header=False, index=False)
    else:
        new_df.to_csv(DATASET_PATH, index=False)

    return len(rows)


def log_labeled(rows):
    with open(LOG_FILE, "a") as f:
        f.write(f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Added {len(rows)} labeled entries:\n")
        for r in rows:
            f.write(f"  proto={r.get('proto','?')} port={r.get('dest_port_zeek','?')} label={r.get('label_tactic','?')}\n")


def ask_retrain():
    print(f"\n{SEPARATOR}")
    ans = input("  Retrain the model now? (y/n): ").strip().lower()
    if ans == "y":
        print("\n[+] Starting retraining — this may take a few minutes...\n")
        result = subprocess.run(
            ["python3", TRAINING_SCRIPT],
            cwd=os.path.dirname(TRAINING_SCRIPT)
        )
        if result.returncode == 0:
            print("\n[✓] Retraining complete! Restart backend.py to load the new model.")
        else:
            print("\n[!] Retraining failed. Check the output above for errors.")
    else:
        print("  Skipped. Run 'python3 training_randomforest.py' manually when ready.")


def count_new_entries_today():
    """Count how many entries were added today from the log."""
    if not os.path.exists(LOG_FILE):
        return 0
    today = datetime.now().strftime("%Y-%m-%d")
    count = 0
    with open(LOG_FILE, "r") as f:
        for line in f:
            if today in line and "Added" in line:
                try:
                    count += int(line.strip().split("Added")[1].split("labeled")[0].strip())
                except Exception:
                    pass
    return count


def manual_mode():
    """Fallback: manually enter traffic details if no live CSV exists."""
    print("\n[i] Manual mode — describe the traffic you ran:\n")
    row = {}

    row["proto"] = input("  Protocol (tcp/udp/icmp): ").strip() or "tcp"
    row["dest_port_zeek"] = input("  Destination port (e.g. 22, 80, 21): ").strip() or "0"
    row["duration"] = input("  Approx duration in seconds (e.g. 0.5): ").strip() or "0"
    row["orig_ip_bytes"] = input("  Bytes sent (approx, e.g. 500): ").strip() or "0"
    row["resp_ip_bytes"] = input("  Bytes received (approx, e.g. 200): ").strip() or "0"
    row["orig_pkts"] = input("  Packets sent (approx, e.g. 5): ").strip() or "0"
    row["resp_pkts"] = input("  Packets received (approx, e.g. 3): ").strip() or "0"
    row["conn_state"] = input("  Connection state (e.g. SF, REJ, S0, RSTO): ").strip() or "SF"
    row["history"] = input("  History (e.g. ShADad, D, Dd): ").strip() or "D"

    label = pick_label()
    if label in (None, "skip"):
        print("  Skipped.")
        return []

    row["label_tactic"] = label
    row["label"] = 1 if label != "none" else 0
    return [row]


def main():
    banner()

    print("\n  [1] Label from live traffic (auto)")
    print("  [2] Enter traffic manually")
    print("  [q] Quit")
    mode = input("\nChoose mode: ").strip().lower()

    if mode == "q":
        return

    labeled_rows = []

    # ── AUTO MODE ──────────────────────────────────────────────
    if mode == "1":
        df = load_live_traffic()
        if df is None:
            print("\n  Switching to manual mode...\n")
            labeled_rows = manual_mode()
        else:
            total = len(df)
            for i, (idx, row) in enumerate(df.iterrows(), 1):
                show_entry(row, i, total)
                label = pick_label()

                if label is None:   # quit
                    break
                if label == "skip":
                    continue

                row = row.copy()
                row["label_tactic"] = label
                row["label"] = 1 if label != "none" else 0
                labeled_rows.append(row.to_dict())

    # ── MANUAL MODE ────────────────────────────────────────────
    elif mode == "2":
        while True:
            rows = manual_mode()
            labeled_rows.extend(rows)
            again = input("\n  Add another entry? (y/n): ").strip().lower()
            if again != "y":
                break

    # ── SAVE ───────────────────────────────────────────────────
    if not labeled_rows:
        print("\n[i] Nothing to save. Exiting.")
        return

    added = append_to_dataset(labeled_rows)
    log_labeled(labeled_rows)

    print(f"\n{SEPARATOR}")
    print(f"  [✓] {added} entries added to dataset.")
    print(f"  Dataset: {DATASET_PATH}")
    print(SEPARATOR)

    # ── RETRAIN CHECK ──────────────────────────────────────────
    total_today = count_new_entries_today()
    print(f"\n  Total new entries added today: {total_today}")

    if total_today >= RETRAIN_AFTER:
        print(f"  [!] Reached {RETRAIN_AFTER}+ new entries — retraining recommended.")
        ask_retrain()
    else:
        remaining = RETRAIN_AFTER - total_today
        print(f"  Add {remaining} more entries to trigger retrain prompt.")
        manual_retrain = input("\n  Retrain now anyway? (y/n): ").strip().lower()
        if manual_retrain == "y":
            ask_retrain()

    print(f"\n[✓] Done. Log saved to {LOG_FILE}\n")


if __name__ == "__main__":
    main()
