#!/bin/sh
# OKE Workload Identity extraction -- run from inside any pod on an Enhanced OKE cluster.
# Outputs the RPST and private key needed to load resource-principal creds in OCInferno.
# Live-validated on OKE 1.35.2 / Oracle Linux 8.
#
# Requirements (all present on standard OKE node images, no installs needed):
#   openssl, curl, awk, sed, base64
#
# Usage: sh oke_wi_extract.sh
# Then load into OCInferno:
#   resource-principal CRED_NAME --token-file /tmp/oke_rpst.jwt \
#     --private-key-file /tmp/oke_key.pem --region REGION
set -e

SA=/var/run/secrets/kubernetes.io/serviceaccount
PROXYMUX="https://${KUBERNETES_SERVICE_HOST}:12250/resourcePrincipalSessionTokens"

# 1. Generate ephemeral RSA keypair (this session only)
openssl genrsa -out /tmp/oke_key.pem 2048 2>/dev/null
openssl rsa -in /tmp/oke_key.pem -pubout -out /tmp/oke_pub.pem 2>/dev/null

# 2. Encode public key as JSON string (awk writes each PEM line + literal \n, no jq needed)
pub_json=$(awk '{printf "%s\\n", $0}' /tmp/oke_pub.pem)
body="{\"podKey\":\"${pub_json}\"}"

# 3. POST to in-cluster proxymux (KUBERNETES_SERVICE_HOST and port 12250 always set on Enhanced clusters)
response=$(curl --max-time 30 -s -X POST "${PROXYMUX}" \
    --cacert "${SA}/ca.crt" \
    -H "Authorization: Bearer $(cat "${SA}/token")" \
    -H "Content-Type: application/json" \
    -d "${body}")

# 4. Decode: proxymux returns a JSON string literal wrapping base64-encoded {"token":"ST$..."}
inner=$(printf '%s' "${response}" | tr -d '"')
decoded=$(printf '%s' "${inner}" | base64 -d 2>/dev/null)
rpst=$(printf '%s' "${decoded}" | sed 's/.*"token":"\([^"]*\)".*/\1/')

if [ -z "${rpst}" ] || [ "${rpst}" = "${decoded}" ]; then
    echo "[!] Exchange failed. Response: ${response:0:120}" >&2
    exit 1
fi

rm -f /tmp/oke_pub.pem
printf '%s' "${rpst}" > /tmp/oke_rpst.jwt

echo "=== RPST (saved to /tmp/oke_rpst.jwt) ==="
echo "${rpst}"
echo ""
echo "=== PRIVATE KEY (saved to /tmp/oke_key.pem) ==="
cat /tmp/oke_key.pem
echo ""
echo "=== Load into OCInferno (run on your machine after copying the files) ==="
echo "resource-principal CRED_NAME --token-file oke_rpst.jwt --private-key-file oke_key.pem --region REGION"
