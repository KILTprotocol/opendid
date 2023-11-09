#!/bin/bash

set -e

ENDPOINT=${ENDPOINT:-peregrine}

# get payment account address and seed from command line arguments
if [ $# -ne 1 ]; then
  if [[ "${ENDPOINT}" == *"peregrine"* ]]; then
    echo "No seed provided, but we are on the testnet, so we will generate a new account and fund it from the faucet."
    echo "This will take some time..."
    PAYMENT_ACCOUNT_SEED=$(node scripts/gen-test-account/dist/main.js)
    echo "Finished generating and funding test payment account."
  else
    echo "Usage: $0 \"<PAYMENT_ACCOUNT_SEED>\""
    exit 1
  fi
else
  PAYMENT_ACCOUNT_SEED=$1
fi

echo "Generating DID..."
node scripts/gen-did/dist/main.js "${PAYMENT_ACCOUNT_SEED}"
DID=$(cat did-document.json | jq -r .uri)
echo "DID: ${DID}"
KEYAGREEMENT_PRIVKEY=$(cat did-secrets.json | jq -r .keyAgreement.privKey)
KEYAGREEMENT_PUBKEY=$(cat did-secrets.json | jq -r .keyAgreement.pubKey)
ATTESTATION_SEED=$(cat did-secrets.json | jq -r .attestation.seed)

echo "Getting key IDs from chain..."
KEYAGREEMENT_KEY_ID=${DID}$(cat did-document.json | jq -r .keyAgreement[0].id)
ATTESTATION_KEY_ID=${DID}$(cat did-document.json | jq -r .assertionMethod[0].id)
SESSION_SECRET=$(openssl rand -hex 64)
JWT_SECRET='super-secret-jwt-secret'

echo "Choosing the right default attester requirements..."
TRUSTED_ATTESTER="did:kilt:4pnfkRn5UurBJTW92d9TaVLR2CqJdY4z5HPjrEbpGyBykare" # Spiritnet SKYC
CTYPE_HASH="0x3291bb126e33b4862d421bfaa1d2f272e6cdfc4f96658988fbcffea8914bd9ac" # Email
if [[ "${ENDPOINT}" == *"peregrine"* ]]; then
  TRUSTED_ATTESTER="did:kilt:4pehddkhEanexVTTzWAtrrfo2R7xPnePpuiJLC7shQU894aY" # Peregrine SKYC
fi

echo "Writing login config file to config.yaml..."

cat > config.yaml <<EOF
# OpenDID Config File

# server config
host: 0.0.0.0
port: 3001
basePath: /srv
production: false
kiltEndpoint: ${ENDPOINT}

# session config
# contains the keyUri, naclSecretKey, naclPublicKey and sessionKey used to communicate with the identity extension
session:
  # key uri of the key agreement key of the verifiers DID
  keyUri: ${KEYAGREEMENT_KEY_ID}
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
  secretKey: "${JWT_SECRET}"
  publicKey: "${JWT_SECRET}"
  algorithm: HS256

# well known DID
wellKnownDid:
  did: ${DID}
  origin: http://localhost:3001
  keyUri: ${ATTESTATION_KEY_ID}
  seed: "${ATTESTATION_SEED}"

# client configs
clients:
  example-client:
    # credential requirements
    # contains the credential requirements for the verifiers DID
    # if the user provides ANY of the listed credentials, the login is successful
    requirements:
      - cTypeHash: "${CTYPE_HASH}"
        trustedAttesters: ["${TRUSTED_ATTESTER}"]
        requiredProperties: ["Email"]
    # valid redirect urls for this client
    redirectUrls:
      - http://localhost:1606/callback.html
EOF

mv config.yaml did-secrets.json did-document.json /data/

