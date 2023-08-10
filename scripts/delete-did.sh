#!/bin/bash

set -e

# get payment account address and seed from command line arguments
if [ $# -ne 1 ]; then
    echo "Usage: $0 \"<payment account seed>\""
    exit 1
fi
PAYMENT_ACCOUNT_SEED=$1
PAYMENT_ACCOUNT_ADDRESS=$(kiltctl util account from-seed --seed "${PAYMENT_ACCOUNT_SEED}")
echo "Payment account address: ${PAYMENT_ACCOUNT_ADDRESS}"

# get did and auth seed
DID=$(cat did-secrets.json | jq -r '.did')
AUTH_SEED=$(cat did-secrets.json | jq -r '.authentication.seed')

kiltctl tx did delete | \
kiltctl tx did authorize \
    --did "${DID}" \
    --submitter "${PAYMENT_ACCOUNT_ADDRESS}" \
    --seed "${AUTH_SEED}" | \
kiltctl tx sign --seed "${PAYMENT_ACCOUNT_SEED}" | \
kiltctl tx submit --wait-for finalized

echo "DID deleted."