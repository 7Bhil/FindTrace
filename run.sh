#!/bin/bash

# FindTrace 2.0 - Auto-Launch Script

VENV_PATH="./venv"

if [ ! -d "$VENV_PATH" ]; then
    echo "[!] Virtual environment not found. Creating one..."
    python3 -m venv venv
    ./venv/bin/pip install -r requirements.txt
fi

echo "[*] Launching FindTrace 2.0..."
./venv/bin/python findtrace.py
