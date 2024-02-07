#!/bin/bash

set -e

# get payment account address and seed from command line arguments
if [ $# -ne 1 ]; then
    echo "Usage: $0 \"<PAYMENT_ACCOUNT_SEED>\""
    exit 1
fi
PAYMENT_ACCOUNT_SEED=$1
if [[ ${ENDPOINT} == "spiritnet" ]]; then
  TRUSTED_ATTESTER="did:kilt:4pnfkRn5UurBJTW92d9TaVLR2CqJdY4z5HPjrEbpGyBykare"
elif [[ ${ENDPOINT} == "peregrine" ]]; then
  TRUSTED_ATTESTER="did:kilt:4pehddkhEanexVTTzWAtrrfo2R7xPnePpuiJLC7shQU894aY"
else
  echo "Usage: docker run -e \"ENDPOINT=spiritnet\" || docker run -e \"ENDPOINT=peregrine "
  exit 1
fi
echo "Generating DID..."
npx ts-node scripts/gen-did/main.ts "${PAYMENT_ACCOUNT_SEED}"
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
  # time in seconds a session lasts as default of 60 minutes
  sessionTtl: 3600

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
    # w3n:socialkyc on spiritnet or w3n:attester on peregrine are added as example trustedAttesters for email credential
    requirements:
      - cTypeHash: "0x3291bb126e33b4862d421bfaa1d2f272e6cdfc4f96658988fbcffea8914bd9ac"
        trustedAttesters: ["${TRUSTED_ATTESTER}"]
        requiredProperties: ["Email"]
    # valid redirect urls for this client
    redirectUrls:
      - http://localhost:1606/callback.html
EOF

mv config.yaml did-secrets.json did-document.json /data/

