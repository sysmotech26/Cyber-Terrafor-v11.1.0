#!/data/data/com.termux/files/usr/bin/bash
set -e
BASE="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
pkg update -y
pkg install -y python clang
pkg install -y nmap || true
python3 -m venv "$BASE/.venv"
"$BASE/.venv/bin/python" -m pip install --upgrade pip
"$BASE/.venv/bin/python" -m pip install -r "$BASE/requirements.txt"
clang++ -std=c++17 -O2 "$BASE/cpp/tor_hash.cpp" -o "$BASE/build/cthash" || true
chmod +x "$BASE/cyber-terrafor"
echo "[+] Cyber Terrafor Professional v10.0 installed. Run: ./cyber-terrafor"
