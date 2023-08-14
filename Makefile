PAYMENT_SEED="eye angry flavor pumpkin require oppose cigar fringe eight breeze valley digital"

all: images

images: dauth-image dauth-setup-image demo-project-image

run: images setup 
	podman run -d --name dauth \
		-v ./config.yaml:/app/config.yaml \
		quay.io/kilt/dauth:latest

kill:
	podman rm -f dauth

push: images
	podman push quay.io/kilt/dauth:latest
	podman push quay.io/kilt/dauth-setup:latest
	podman push quay.io/kilt/dauth-demo-project:latest

setup: config.yaml
config.yaml: dauth-setup-image
	podman run --rm -it -v $(shell pwd):/data quay.io/kilt/dauth-setup:latest $(PAYMENT_SEED)

delete-did: dauth-setup-image
	podman run --rm -it -v $(shell pwd):/data -w /data --entrypoint /bin/bash quay.io/kilt/dauth-setup:latest /app/scripts/delete-did.sh $(PAYMENT_SEED)

binary: target/release/kilt-login
target/release/kilt-login: $(shell find ./src -type f -name '*.rs')
	cargo build --release

frontend: login-frontend/dist/index.html
login-frontend/dist/index.html: $(shell find ./login-frontend/src -type f)
	cd login-frontend && yarn && yarn build

dauth-image: .dauth-image
.dauth-image: scripts/Containerfile target/release/kilt-login frontend
	podman build -t quay.io/kilt/dauth:latest -f scripts/Containerfile .
	touch .dauth-image

dauth-setup-image: .dauth-setup-image
.dauth-setup-image: scripts/setup.Containerfile
	podman build -t quay.io/kilt/dauth-setup:latest -f scripts/setup.Containerfile .
	touch .dauth-setup-image

demo-project/index.js: demo-project/main.ts 
	cd demo-project && yarn && yarn build

demo-project-image: .demo-project-image
.demo-project-image: scripts/demo.Containerfile demo-project/index.js $(shell find ./demo-project/demo-frontend)
	podman build -t quay.io/kilt/dauth-demo-project:latest -f scripts/demo.Containerfile .
	touch .demo-project-image