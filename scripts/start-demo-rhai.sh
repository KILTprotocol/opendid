#!/bin/bash

# create a pod to hold backend and frontend
podman pod create --replace -p 1606:1606 -p 3001:3001 -n openid-test

# start the simple auth relay app
podman run -d --rm \
  --pod openid-test \
  --name openid-backend \
  -e RUST_LOG=info \
  -v $(pwd)/config.yaml:/app/config.yaml \
  -v $(pwd)/scripts/example-checks:/app/checks \
  quay.io/kilt/simple-auth-relay-app:latest

# start the example client frontend
podman run -d --rm \
  --pod openid-test \
  --name demo-frontend \
  quay.io/kilt/simple-auth-relay-app-demo

exit $?
