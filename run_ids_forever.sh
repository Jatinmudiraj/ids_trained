#!/bin/bash
# run_ids_forever.sh — Robust background runner for IDS

BASE_DIR="/raid/home/geeta/geeta/Trained_IDS"
PYTHON_BIN="python3"
LOG_OUT="$BASE_DIR/ids_cli_final.log"
SIM_LOG="$BASE_DIR/simulator.log"
PASSWORD="geeta"

echo "[*] Starting ANTIGRAVITY IDS Persistence Layer..."

# 1. Ensure simulator is running
if ! ps aux | grep -v grep | grep "simulate_logs.py" > /dev/null; then
    echo "[*] Starting log simulator..."
    nohup $PYTHON_BIN $BASE_DIR/simulate_logs.py > $SIM_LOG 2>&1 &
fi

# 2. Run IDS in a loop (auto-restart if it dies)
echo "[*] Launching IDS CLI with auto-restart..."
while true; do
    echo "[$(date)] IDS CLI started." >> $LOG_OUT
    echo "$PASSWORD" | sudo -S $PYTHON_BIN -u $BASE_DIR/cli.py >> $LOG_OUT 2>&1
    echo "[$(date)] IDS CLI exited with code $?. Restarting in 5s..." >> $LOG_OUT
    sleep 5
done
