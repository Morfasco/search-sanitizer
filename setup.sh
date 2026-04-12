#!/usr/bin/env bash
# Quick setup for search-sanitizer
set -euo pipefail

echo "search-sanitizer setup"
echo ""

# Create .env from example if missing
if [[ ! -f .env ]]; then
    echo "[1/4] Creating .env from template..."
    cp .env.example .env
    echo "  ✓ .env created — edit it to configure your LLM"
    echo ""
    echo "  ┌──────────────────────────────────────────────────┐"
    echo "  │  IMPORTANT: Edit .env before continuing.         │"
    echo "  │                                                   │"
    echo "  │  At minimum, verify:                              │"
    echo "  │    OLLAMA_URL    — where your LLM is running     │"
    echo "  │    FILTER_MODEL  — your preferred small model    │"
    echo "  │                                                   │"
    echo "  │  Then re-run: bash setup.sh                       │"
    echo "  └──────────────────────────────────────────────────┘"
    echo ""
    read -r -p "  Edit .env now and continue? [y/N]: " resp
    if [[ ! "$resp" =~ ^[Yy]$ ]]; then
        echo "  Edit .env, then re-run setup.sh"
        exit 0
    fi
else
    echo "[1/4] .env exists"
fi

# Source .env for local use
set -a; source .env; set +a

# Generate SearXNG secret
if [[ ! -f searxng/settings.yml ]]; then
    echo "[2/4] Generating SearXNG config..."
    cp searxng/settings.yml.example searxng/settings.yml
    SECRET=$(openssl rand -hex 32)
    sed -i.bak "s/CHANGE_ME_GENERATE_WITH_openssl_rand_-hex_32/$SECRET/" searxng/settings.yml
    rm -f searxng/settings.yml.bak
    echo "  ✓ SearXNG secret generated"
else
    echo "[2/4] SearXNG config exists"
fi

# Check LLM
echo "[3/4] Checking LLM at $OLLAMA_URL..."
if curl -sf "$OLLAMA_URL" >/dev/null 2>&1 || curl -sf "${OLLAMA_URL}/api/tags" >/dev/null 2>&1; then
    echo "  ✓ LLM endpoint reachable"
else
    echo "  ⚠ LLM not reachable at $OLLAMA_URL"
    echo "    If using Ollama: ollama serve"
    echo "    If using LM Studio: start the server"
fi

# Build and start
echo "[4/4] Building and starting..."
docker compose build
docker compose up -d

echo ""
echo "Waiting for health..."
for i in $(seq 1 20); do
    sleep 3
    if curl -sf http://localhost:8000/health >/dev/null 2>&1; then
        echo "  ✓ Healthy"
        curl -s http://localhost:8000/health | python3 -m json.tool 2>/dev/null || true
        break
    fi
    printf "\r  waiting... %ds" $((i * 3))
done

echo ""
echo "Ready!"
echo "  Test:     python3 redteam.py"
echo "  Config:   cat .env"
echo "  Logs:     docker compose logs agent -f"
