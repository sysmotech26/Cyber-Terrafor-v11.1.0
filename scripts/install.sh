set -e
BASE="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
python3 -m venv "$BASE/.venv"
"$BASE/.venv/bin/python" -m pip install --upgrade pip
"$BASE/.venv/bin/python" -m pip install -r "$BASE/requirements.txt"
if command -v clang++ >/dev/null 2>&1; then
  clang++ -std=c++17 -O2 "$BASE/cpp/tor_hash.cpp" -o "$BASE/build/cthash" || true
fi
chmod +x "$BASE/cyber-terrafor"
echo "[+] Cyber Terrafor Professional v11.1.0 installed. Run: ./cyber-terrafor"
