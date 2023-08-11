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

# generate seeds
echo "Generate seeds..."
AUTH_SEED=$(kiltctl util seed generate)
ATTESTATION_SEED=$(kiltctl util seed generate)
KEYAGREEMENT_SEED=$(kiltctl util seed generate)
echo "Done."

# generate accounts and keys
echo "Generate accounts and keys..."
AUTH_ACCOUNT_ADDRESS=$(kiltctl util account from-seed --seed "${AUTH_SEED}")
ATTESTATION_KEY=$(kiltctl util keys from-seed --seed "${ATTESTATION_SEED}")
KEYAGREEMENT_GEN_KEY_OUTPUT=$(node ./scripts/gen-key/gen-key.js "${KEYAGREEMENT_SEED}")
KEYAGREEMENT_PUBKEY=$(echo "${KEYAGREEMENT_GEN_KEY_OUTPUT}" | jq -r '.pubKey')
KEYAGREEMENT_PRIVKEY=$(echo "${KEYAGREEMENT_GEN_KEY_OUTPUT}" | jq -r '.privKey')
echo "Done."

echo "Writing did-secrets.json..."
cat > /data/did-secrets.json <<EOF
{
    "did": "did:kilt:${AUTH_ACCOUNT_ADDRESS}",
    "authentication" :{
        "pubKey": "${AUTH_ACCOUNT_ADDRESS}",
        "seed": "${AUTH_SEED}"
    },
    "attestation": {
        "pubKey": "${ATTESTATION_KEY}",
        "seed": "${ATTESTATION_SEED}"
    },
    "keyAgreement": {
        "pubKey": "${KEYAGREEMENT_PUBKEY}",
        "seed": "${KEYAGREEMENT_SEED}",
        "privKey": "${KEYAGREEMENT_PRIVKEY}"
    }    
}
EOF

echo "Keys and Accounts generated, creating on-chain DID..."
kiltctl tx did create \
    --submitter "${PAYMENT_ACCOUNT_ADDRESS}" \
    --seed "${AUTH_SEED}" \
    --attestation-key "${ATTESTATION_KEY}" | \
    kiltctl tx sign --seed "${PAYMENT_ACCOUNT_SEED}" | \
    kiltctl tx submit --wait-for finalized

echo "On-chain DID created, adding key-agreement key..."

kiltctl tx did add-key-agreement-key -t x25519 -k "${KEYAGREEMENT_PUBKEY}" | \
    kiltctl tx did authorize \
        --did "did:kilt:${AUTH_ACCOUNT_ADDRESS}" \
        --submitter "${PAYMENT_ACCOUNT_ADDRESS}" \
        --seed "${AUTH_SEED}" | \
    kiltctl tx sign --seed "${PAYMENT_ACCOUNT_SEED}" | \
    kiltctl tx submit --wait-for finalized

echo "Key-agreement key added."

echo "Getting key IDs from chain..."
OUTPUT=$(kiltctl storage did did --did did:kilt:${AUTH_ACCOUNT_ADDRESS})
KEYAGREEMENT_KEY_ID=$(echo "${OUTPUT}" | grep -2 PublicEncryptionKey | head -1 | tr -d ' ,')
ATTESTATION_KEY_ID=$(echo "${OUTPUT}" | grep -1 attestation_key | tail -1 | tr -d ' ,')

# generate random session secret and JWT secret
SESSION_SECRET=$(openssl rand -hex 64)
JWT_SECRET=$(openssl rand -hex 64)

echo "Writing login config file to config.yaml..."

cat > /data/config.yaml <<EOF
# kiltlogin config file

# server config
host: 0.0.0.0
port: 3001
basePath: /srv

# session config
# contains the keyUri, naclSecretKey, naclPublicKey and sessionKey used to communicate with the identity extension
session:
  # key uri of the key agreement key of the verifiers DID
  keyUri: did:kilt:${AUTH_ACCOUNT_ADDRESS}#${KEYAGREEMENT_KEY_ID}
  # nacl secret key of the key agreement key of the verifiers DID
  naclSecretKey: "${KEYAGREEMENT_PRIVKEY}"
  # nacl public key of the key agreement key of the verifiers DID
  naclPublicKey: "${KEYAGREEMENT_PUBKEY}"
  # session key used to encrypt the session data, needs to be the same on all instances
  sessionKey: "0x${SESSION_SECRET}"

# credential requirements
# contains the credential requirements for the verifiers DID
# if the user provides ANY of the listed credentials, the login is successful
credentialRequirements:
  - cTypeHash: "0x3291bb126e33b4862d421bfaa1d2f272e6cdfc4f96658988fbcffea8914bd9ac"
    trustedAttesters: ["did:kilt:4pnfkRn5UurBJTW92d9TaVLR2CqJdY4z5HPjrEbpGyBykare"]
    requiredProperties: ["Email"]

# jwt config
# contains the jwt config for the access and refresh tokens
jwt:
  tokenIssuer: did:kilt:${AUTH_ACCOUNT_ADDRESS}
  accessTokenLifetime: 60
  accessTokenAudience: application
  refreshTokenLifetime: 600
  refreshTokenAudience: authentication
  tokenSecret: "0x${JWT_SECRET}"

# well known DID
wellKnownDid:
  did: did:kilt:${AUTH_ACCOUNT_ADDRESS}
  origin: http://localhost:3001
  keyUri: did:kilt:${AUTH_ACCOUNT_ADDRESS}#${ATTESTATION_KEY_ID}
  seed: "${ATTESTATION_SEED}"
EOF
