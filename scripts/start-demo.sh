#!/bin/bash

# create a pod to hold backend and frontend
podman pod create --replace -p 1606:1606 -p 3001:3001 -n opendid-test

# start the simple auth relay app
docker run -d --rm \
  --pod opendid-test \
  --name opendid-backend \
  -e RUST_LOG=info \
  -v $(pwd)/config.yaml:/app/config.yaml \
  docker.io/kiltprotocol/opendid:latest

# start the example client frontend
docker run -d --rm \
  --pod opendid-test \
  --name demo-frontend \
  docker.io/kiltprotocol/opendid-demo:latest

exit $?
