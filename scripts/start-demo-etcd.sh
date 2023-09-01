#!/bin/bash

#########
# NOTE:
# If you run this, visit localhost:1606 and click login, you will not use the "new-client" that is configured below.
# Anyhow, you can still use the "new-client" by opening the developer console and changing the client_id in the
# login url to "new-client".
#

# create the pod to hold the backend, frontend, and etcd
podman pod create --replace -p 1606:1606 -p 3001:3001 -p 2379:2379 sara-test

# start single node etcd deployment
podman run -d --rm --pod sara-test -v /usr/share/ca-certificates/:/etc/ssl/certs \
  --name etcd quay.io/coreos/etcd \
  etcd \
  -name etcd0 \
  -advertise-client-urls http://127.0.0.1:2379,http://127.0.0.1:4001 \
  -listen-client-urls http://0.0.0.0:2379,http://0.0.0.0:4001 \
  -initial-advertise-peer-urls http://127.0.0.1:2380 \
  -listen-peer-urls http://0.0.0.0:2380 \
  -initial-cluster-token etcd-cluster-1 \
  -initial-cluster etcd0=http://127.0.0.1:2380 \
  -initial-cluster-state new

# start the example client frontend
podman run -d --rm \
  --pod sara-test \
  --name demo-frontend \
  quay.io/kilt/simple-auth-relay-app-demo

# start the simple auth relay app
podman run -d --rm \
  --pod sara-test \
  --name sara-backend \
  -e RUST_LOG=info \
  -v $(pwd)/config.yaml:/app/config.yaml \
  quay.io/kilt/simple-auth-relay-app:latest

# add a client to etcd
CLIENT_SPEC=$(cat <<EOF
{
  "requirements": [{
    "cTypeHash":"0x3291bb126e33b4862d421bfaa1d2f272e6cdfc4f96658988fbcffea8914bd9ac",
    "trustedAttesters":["did:kilt:4pnfkRn5UurBJTW92d9TaVLR2CqJdY4z5HPjrEbpGyBykare"],
    "requiredProperties": ["Email"]
  }],
  "redirectUrls": ["http://localhost:1606/callback.html"]
}
EOF
)
CLIENT_SPEC=$(echo $CLIENT_SPEC | jq -c)
etcdctl put /sara/clients/new-client "${CLIENT_SPEC}"

exit $?