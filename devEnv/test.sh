#!/bin/bash

BASE_URL="http://whoami.localhost"
TRAEFIK_DASHBOARD="http://dashboard.localhost:8080"

echo "======================================"
echo "Traefik Get Real IP Plugin Test Suite"
echo "======================================"
echo ""

test_scenario() {
    local test_name="$1"
    local headers=("${@:2:$#-2}")  # 从第二个到倒数第二个
    local expected_ip="${@: -1}"  # 最后一个参数是期望的IP
    local header_count=$(( $# - 2 ))  # header参数的数量

    echo "--------------------------------------"
    echo "Test: $test_name"
    echo "--------------------------------------"
    echo "Request headers:"
    for ((i=0; i<header_count; i++)); do
        echo "  ${headers[i]}"
    done
    echo "header_count: $header_count"

    # 执行curl命令
    if [ $header_count -gt 0 ]; then
        response=$(curl -s -w "\n%{http_code}" -H "Host: whoami.localhost" "${headers[@]}" "$BASE_URL")
    else
        response=$(curl -s -w "\n%{http_code}" -H "Host: whoami.localhost" "$BASE_URL")
    fi

    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | sed '$d')

    echo "HTTP Status: $http_code"
    echo ""

    if [ "$http_code" != "200" ]; then
        echo "❌ FAILED: Expected HTTP 200, got $http_code"
        echo "$body"
        echo ""
        return 1
    fi

    real_ip=$(echo "$body" | grep -i "X-Real-Ip" | awk '{for(i=1;i<=NF;i++){if($i~/X-Real-Ip:/){print $(i+1)}}}')

    echo "Response body:"
    # echo "$body" | grep -E "(X-Real-Ip|X-Forwarded-For|RemoteAddr)" | sed 's/^/  /'
    echo "$body" | sed -n '/^RemoteAddr:/,$p'
    echo ""

    if [ -n "$expected_ip" ]; then
        if echo "$body" | grep -qi "X-Real-Ip: $expected_ip"; then
            echo "✅ PASSED: X-Real-Ip is correctly set to $expected_ip"
        else
            echo "❌ FAILED: Expected X-Real-Ip to be $expected_ip, but got $real_ip"
            return 1
        fi
    else
        echo "✅ PASSED: Request successful"
    fi
    echo ""
}

echo "Checking if Traefik is running..."
# if ! curl -s -f "$TRAEFIK_DASHBOARD/api/http" > /dev/null; then
#     echo "❌ ERROR: Traefik is not responding. Please start the docker-compose first:"
#     echo "   cd devEnv && docker-compose up -d"
#     exit 1
# fi
# echo "✅ Traefik is running"
# echo ""

test_scenario \
    "Cloudflare CDN - Extract IP from Cf-Connecting-Ip" \
    "-H" "X-From-Cdn: cf-foo" \
    "-H" "Cf-Connecting-Ip: 203.0.113.1" \
    "203.0.113.1"

test_scenario \
    "CDN2 - Extract IP from Client-Ip" \
    "-H" "X-From-Cdn: mf-bar" \
    "-H" "Client-Ip: 198.51.100.1" \
    "198.51.100.1"

test_scenario \
    "CDN3 - Extract first IP from X-Forwarded-For" \
    "-H" "X-From-Cdn: mf-fun" \
    "-H" "X-Forwarded-For: 192.0.2.1, 203.0.113.2, 198.51.100.2" \
    "192.0.2.1"

test_scenario \
    "CDN3 - Skip invalid IPs in X-Forwarded-For" \
    "-H" "X-From-Cdn: mf-fun" \
    "-H" "X-Forwarded-For: invalid-ip,192.0.2.2" \
    "192.0.2.2"

test_scenario \
    "Direct connection - Use RemoteAddr (wildcard proxy)" \
    "-H" "no: no" \
    ""

echo "--------------------------------------"
echo "Test: Cloudflare CDN with OverwriteXFF - Verify X-Forwarded-For is overwritten"
echo "--------------------------------------"
echo ""
response=$(curl -s -w "\n%{http_code}" \
    -H "Host: whoami.localhost" \
    -H "X-From-Cdn: cf-foo" \
    -H "Cf-Connecting-Ip: 203.0.113.10" \
    -H "X-Forwarded-For: 192.0.2.100" \
    "$BASE_URL")
body=$(echo "$response" | sed '$d')

echo "$body" | sed -n '/^RemoteAddr:/,$p'

if echo "$body" | grep -qi "X-Real-Ip: 203.0.113.10" && echo "$body" | grep -qi "X-Forwarded-For: 203.0.113.10"; then
    echo "✅ PASSED: X-Forwarded-For was correctly overwritten to match X-Real-Ip"
else
    echo "❌ FAILED: Expected X-Forwarded-For to be 203.0.113.10"
fi
echo ""

# Test 7: Test with IP and port in header
test_scenario \
    "CDN2 - IP with port number in Client-Ip" \
    "-H" "X-From-Cdn: mf-bar" \
    "-H" "Client-Ip: 198.51.100.5:8080" \
    "198.51.100.5"

test_scenario \
    "Multiple CDN headers - First matching config should win" \
    "-H" "X-From-Cdn: cf-foo" \
    "-H" "Cf-Connecting-Ip: 203.0.113.99" \
    "-H" "Client-Ip: 198.51.100.99" \
    "203.0.113.99"

test_scenario \
    "Unrecognized CDN value - Fallback to wildcard RemoteAddr" \
    "-H" "X-From-Cdn: unknown-cdn" \
    "-H" "Client-Ip: 198.51.100.100" \
    ""

echo "======================================"
echo "Test suite completed!"
echo "======================================"
echo ""
echo "To view Traefik dashboard and plugin logs:"
echo "  Open: $TRAEFIK_DASHBOARD"
echo ""
echo "To restart the plugin after code changes:"
echo "  cd devEnv && docker-compose restart"
echo ""
echo "To view plugin logs:"
echo "  docker-compose -f devEnv/docker-compose.yaml logs -f traefik"
