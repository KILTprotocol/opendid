PAYMENT_SEED="eye angry flavor pumpkin require oppose cigar fringe eight breeze valley digital"

all: images

images: dauth-image dauth-setup-image dauth-frontend-image

run: images setup 
	podman pod create --name dauth -p 3001:3001 --replace
	podman run -d --pod dauth --name dauth-backend \
		-v ./config.yaml:/app/config.yaml \
		quay.io/kilt/dauth:latest
	podman run -d --pod dauth --name dauth-frontend \
		quay.io/kilt/dauth-frontend:latest
	podman run -d --pod dauth --name dauth-ingress \
		-v ./scripts/Caddyfile:/etc/caddy/Caddyfile \
		docker.io/library/caddy:latest

kill:
	podman pod rm -f dauth 

push: images
	podman push quay.io/kilt/dauth:latest
	podman push quay.io/kilt/dauth-setup:latest
	podman push quay.io/kilt/dauth-frontend:latest

setup: config.yaml
config.yaml:
	podman run --rm -it -v $(shell pwd):/data quay.io/kilt/dauth-setup:latest $(PAYMENT_SEED)

delete-did:
	podman run --rm -it -v $(shell pwd):/data -w /data --entrypoint /bin/bash quay.io/kilt/dauth-setup:latest /app/scripts/delete-did.sh $(PAYMENT_SEED)

binary: target/release/kilt-login
target/release/kilt-login: $(shell find ./src -type f -name '*.rs')
	cargo build --release

dauth-image: .dauth-image
.dauth-image: scripts/Containerfile target/release/kilt-login
	podman build -t quay.io/kilt/dauth:latest -f scripts/Containerfile .
	touch .dauth-image

dauth-setup-image: .dauth-setup-image
.dauth-setup-image: scripts/setup.Containerfile
	podman build -t quay.io/kilt/dauth-setup:latest -f scripts/setup.Containerfile .
	touch .dauth-setup-image

dauth-frontend-image: .dauth-frontend-image
.dauth-frontend-image: scripts/frontend.Containerfile $(shell find ./example-frontend/App.tsx -type f)
	podman build -t quay.io/kilt/dauth-frontend:latest -f scripts/frontend.Containerfile .
	touch .dauth-frontend-image