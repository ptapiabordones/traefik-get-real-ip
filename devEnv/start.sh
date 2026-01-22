#!/bin/bash

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=========================================="
echo "Traefik Get Real IP Plugin - Quick Start"
echo "=========================================="
echo ""

if ! docker info > /dev/null 2>&1; then
    echo "❌ ERROR: Docker is not running. Please start Docker first."
    exit 1
fi

echo "✅ Docker is running"
echo ""

echo "Starting Traefik with real-ip plugin..."
cd "$SCRIPT_DIR"
docker-compose up -d

echo ""
echo "=========================================="
echo "Environment is running!"
echo "=========================================="
echo ""
echo "Services:"
echo "  • Traefik Dashboard: http://dashboard.localhost:8080"
echo "  • whoami service:   http://whoami.localhost (port 80)"
echo ""
echo "Next steps:"
echo "  1. Run the test suite:"
echo "     ./test.sh"
echo ""
echo "  2. View Traefik logs:"
echo "     docker-compose logs -f traefik"
echo ""
echo "  3. Stop the environment:"
echo "     docker-compose down"
echo ""
echo "  4. Restart after code changes:"
echo "     docker-compose restart traefik"
echo ""
