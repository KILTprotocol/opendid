#!/bin/bash

set -e

# get payment account address and seed from command line arguments
if [ $# -ne 1 ]; then
    echo "Usage: $0 \"<payment account seed>\""
    exit 1
fi
PAYMENT_ACCOUNT_SEED=$1

DID=$(npx ts-node scripts/gen-did/main.ts "${PAYMENT_ACCOUNT_SEED}")
KEYAGREEMENT_PRIVKEY=$(cat did-secret.json | jq -r .keyAgreementKey.privKey)
KEYAGREEMENT_PUBKEY=$(cat did-secret.json | jq -r .keyAgreementKey.pubKey)
ATTESTATION_SEED=$(cat did-secret.json | jq -r .attestation.seed)

echo "Getting key IDs from chain..."
OUTPUT=$(kiltctl storage did did --did ${DID})
KEYAGREEMENT_KEY_ID=$(echo "${OUTPUT}" | grep -2 PublicEncryptionKey | head -1 | tr -d ' ,')
ATTESTATION_KEY_ID=$(echo "${OUTPUT}" | grep -1 attestation_key | tail -1 | tr -d ' ,')
SESSION_SECRET=$(openssl rand -hex 64)
JWT_SECRET='super-secret-jwt-secret'

echo "Writing login config file to config.yaml..."

cat > /data/config.yaml <<EOF
# OpenDID Config File

# server config
host: 0.0.0.0
port: 3001
basePath: /srv
production: false

# session config
# contains the keyUri, naclSecretKey, naclPublicKey and sessionKey used to communicate with the identity extension
session:
  # key uri of the key agreement key of the verifiers DID
  keyUri: ${DID}#${KEYAGREEMENT_KEY_ID}
  # nacl secret key of the key agreement key of the verifiers DID
  naclSecretKey: "${KEYAGREEMENT_PRIVKEY}"
  # nacl public key of the key agreement key of the verifiers DID
  naclPublicKey: "${KEYAGREEMENT_PUBKEY}"
  # session key used to encrypt the session data, needs to be the same on all instances
  sessionKey: "0x${SESSION_SECRET}"

# jwt config
# contains the jwt config for the access and refresh tokens
jwt:
  tokenIssuer: ${DID}
  accessTokenLifetime: 60
  accessTokenAudience: application
  refreshTokenLifetime: 600
  refreshTokenAudience: authentication
  tokenSecret: "${JWT_SECRET}"

# well known DID
wellKnownDid:
  did: ${DID}
  origin: http://localhost:3001
  keyUri: ${DID}#${ATTESTATION_KEY_ID}
  seed: "${ATTESTATION_SEED}"

# client configs
clients:
  example-client:
    # credential requirements
    # contains the credential requirements for the verifiers DID
    # if the user provides ANY of the listed credentials, the login is successful
    requirements:
      - cTypeHash: "0x3291bb126e33b4862d421bfaa1d2f272e6cdfc4f96658988fbcffea8914bd9ac"
        trustedAttesters: ["did:kilt:4pnfkRn5UurBJTW92d9TaVLR2CqJdY4z5HPjrEbpGyBykare"]
        requiredProperties: ["Email"]
    # valid redirect urls for this client
    redirectUrls:
      - http://localhost:1606/callback.html
EOF
