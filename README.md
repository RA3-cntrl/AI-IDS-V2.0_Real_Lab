# FedoraDash — AI Intrusion Detection System (V2.0 — Real Lab)

A real-time AI-powered IDS running on Fedora Linux, using machine learning to classify network traffic captured by Zeek, with a live web dashboard.

## Network Topology

```
                         Switch (192.168.2.0/24)
                               │
        ┌──────────────────────┼────────────────────────┐
        │                      │                        │
 Kali (attacker)        Fedora sensor            Windows victim
 192.168.2.30           192.168.2.20              192.168.2.223
 eth0 (bridged)         ens224 PROMISC            (physical PC)
 eth1 (NAT/internet)    ens160 DHCP (internet)
                               │
                         OPNsense GW
                          192.168.2.1
```

**Fedora is a pure sensor — NOT a router.** All machines are on the same flat `/24` subnet. Zeek sniffs passively on `ens224` in promiscuous mode.

---

## Files

| File | Description |
|---|---|
| `backendV2_fedora.py` | Main Flask backend — Zeek log watcher, ML inference, REST API + SSE |
| `dashboard.html` | FedoraDash web UI — dark/light theme, login, real-time alerts |
| `ids_binary_model.pkl` | Trained Random Forest model (generate with `prepare_retrain.py`) |
| `encoder_mappings.json` | Label encoder mappings for categorical features |
| `prepare_retrain.py` | Script to train/retrain the model from `combined_ids_dataset.csv` |
| `combined_ids_dataset.csv` | Training dataset |
| `REBOOT_GUIDE.txt` | Step-by-step instructions after every reboot |

---

## Quick Start

### 1. Setup (first time only)
```bash
python3 -m venv ~/AI-IDS/.venv
source ~/AI-IDS/.venv/bin/activate
pip install flask flask-cors scikit-learn pandas numpy requests urllib3
```

### 2. After every reboot

**Fedora — Terminal 0 (enable promiscuous mode):**
```bash
sudo ip link set ens224 promisc on
```

**Fedora — Terminal 1 (backend):**
```bash
source ~/AI-IDS/.venv/bin/activate
cd ~/AI-IDS
python3 backendV2_fedora.py
```

**Fedora — Terminal 2 (Zeek — sniff on ens224):**
```bash
cd /var/log/zeek
sudo zeek -i ens224
```

**Kali (after reboot — run these 3 commands):**
```bash
sudo ip addr add 192.168.2.30/24 dev eth0
sudo ip link set eth0 up
sudo ip route add 192.168.2.0/24 dev eth0
```

### 3. Open dashboard
```
http://localhost:5050
Login: admin / fedora1337
```

---

## Features

- **Real-time detection** — Zeek captures traffic on `ens224`, backend classifies every connection
- **ML inference** — Random Forest binary classifier (ATTACK / NORMAL)
- **Live dashboard** — SSE stream, connection feed, threat alerts, protocol stats
- **Dark / Light theme** — toggle in the header, preference saved across sessions
- **Simulate attacks** — test the pipeline without real traffic via the dashboard button
- **Export CSV** — download all connections from the dashboard
- **Auto-block** — optionally blocks attacker IPs via OPNsense API (≥90% confidence)
- **DEMO mode** — runs with random predictions when no model file is found

---

## Dashboard Login

| Field | Value |
|---|---|
| Username | `admin` |
| Password | `fedora1337` |

---

## OPNsense Integration (optional — auto-block)

Set credentials as environment variables before starting the backend:
```bash
export OPNSENSE_HOST="https://192.168.2.1"
export OPNSENSE_API_KEY="your-key"
export OPNSENSE_API_SEC="your-secret"
```

The alias `IDS_Blocklist` must already exist in OPNsense → Firewall → Aliases.

---

## Train the Model

```bash
source ~/AI-IDS/.venv/bin/activate
cd ~/AI-IDS
python3 prepare_retrain.py
```

Generates `ids_binary_model.pkl` and `encoder_mappings.json`. Restart the backend to load them.

---

## Whitelist (IPs that will never be blocked)

| IP | Role |
|---|---|
| `192.168.2.1` | OPNsense gateway |
| `192.168.2.20` | Fedora sensor (self) |
| `192.168.2.223` | Windows victim (protected host) |
| `127.0.0.1` / `::1` | Loopback |
| `8.8.8.8` / `8.8.4.4` | DNS |

---

## Running Attack Tests (from Kali)

```bash
# Recon
nmap -sS 192.168.2.223
nmap -A -T4 192.168.2.223

# Service scan
nmap -sV -p 1-1000 192.168.2.223

# SYN flood
sudo hping3 -S --flood -p 80 192.168.2.223

# ICMP flood
sudo hping3 --icmp --flood 192.168.2.223

# RDP brute force (if port 3389 is open)
hydra -l administrator -P /usr/share/wordlists/rockyou.txt rdp://192.168.2.223
```
