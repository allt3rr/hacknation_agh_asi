#!/bin/sh
# Punkt wejścia kontenera ASI.
#
# Jeśli ASI_DATA_KEY nie jest ustawiony, klucz jest generowany i zapisywany w wolumenie danych.
# Klucz leży wtedy obok zaszyfrowanych danych, więc ten tryb nadaje się tylko do testów i demo.
# W produkcji przekaż ASI_DATA_KEY przez zmienną środowiskową lub docker secret.
set -eu

if [ -z "${ASI_DATA_KEY:-}" ]; then
    KEY_FILE="/app/data/.data_key"
    if [ ! -s "$KEY_FILE" ]; then
        echo "[asi] Brak ASI_DATA_KEY, generuję klucz w $KEY_FILE (tryb testowy)" >&2
        umask 077
        asi gen-key > "$KEY_FILE"
    fi
    ASI_DATA_KEY="$(cat "$KEY_FILE")"
    export ASI_DATA_KEY
fi

exec asi "$@"
