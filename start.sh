#!/usr/bin/env bash

# Obtenir le répertoire du script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Charger .env depuis le répertoire du script
set -a
source "$SCRIPT_DIR/.env"
set +a

echo "[1/2] Starting FastAPI on port 8000..."
uvicorn app.api:app --host 0.0.0.0 --port 8000 &
FASTAPI_PID=$!
echo $FASTAPI_PID

echo "[2/2] Starting scanner worker..."
echo ""
python -m app &
APP_PID=$!

# Trap pour tuer les processus à la sortie
trap "echo 'Shutting down...'; kill $FASTAPI_PID $APP_PID 2>/dev/null; exit" SIGINT SIGTERM

# Attendre que les processus se terminent
wait