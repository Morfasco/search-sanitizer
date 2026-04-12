#!/usr/bin/env bash
# Quick setup for search-sanitizer
set -euo pipefail

echo "search-sanitizer setup"
echo ""

# Generate SearXNG secret
if [[ ! -f searxng/settings.yml ]]; then
    echo "[1/3] Generating SearXNG config..."
    cp searxng/settings.yml.example searxng/settings.yml
    SECRET=$(openssl rand -hex 32)
    sed -i.bak "s/CHANGE_ME_GENERATE_WITH_openssl_rand_-hex_32/$SECRET/" searxng/settings.yml
    rm -f searxng/settings.yml.bak
    echo "  ✓ SearXNG secret generated"
else
    echo "[1/3] SearXNG config exists, skipping"
fi

# Check Ollama
echo "[2/3] Checking Ollama..."
if curl -sf http://localhost:11434/api/tags >/dev/null 2>&1; then
    echo "  ✓ Ollama running"
    MODELS=$(curl -s http://localhost:11434/api/tags | python3 -c "import sys,json; print(', '.join(m['name'] for m in json.load(sys.stdin).get('models',[])))" 2>/dev/null || echo "?")
    echo "  Models: $MODELS"
else
    echo "  ⚠ Ollama not running. Start it and pull a model:"
    echo "    ollama pull qwen3:4b"
fi

# Build and start
echo "[3/3] Building containers..."
docker compose build
docker compose up -d

echo ""
echo "Waiting for health..."
for i in $(seq 1 20); do
    sleep 3
    if curl -sf http://localhost:8000/health >/dev/null 2>&1; then
        echo "  ✓ Healthy"
        curl -s http://localhost:8000/health | python3 -m json.tool
        break
    fi
    printf "\r  waiting... %ds" $((i * 3))
done

echo ""
echo "Ready! Test: python3 redteam.py"
