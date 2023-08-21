APP_NAME=simple-auth-relay-app
MAIN_IMAGE="quay.io/kilt/$(APP_NAME)"
SETUP_IMAGE="quay.io/kilt/$(APP_NAME)-setup"
DEMO_IMAGE="quay.io/kilt/$(APP_NAME)-demo"

all: images

images: main-image setup-image demo-image

push: images
	podman push $(MAIN_IMAGE)
	podman push $(SETUP_IMAGE)
	podman push $(DEMO_IMAGE)

setup: config.yaml
config.yaml: setup-image
	podman run --rm -it -v $(shell pwd):/data $(SETUP_IMAGE) $(PAYMENT_SEED)

delete-did: simple-auth-relay-app-setup-image
	podman run --rm -it -v $(shell pwd):/data -w /data --entrypoint /bin/bash $(SETUP_IMAGE) /app/scripts/delete-did.sh $(PAYMENT_SEED)

binary: target/release/simple-auth-relay-app
target/release/simple-auth-relay-app: $(shell find ./src -type f -name '*.rs')
	cargo build --release


main-image: .main-image
.main-image: scripts/Containerfile target/release/simple-auth-relay-app login-frontend/dist/index.html
	podman build -t $(MAIN_IMAGE):latest -f scripts/Containerfile .
	touch .main-image

login-frontend/dist/index.html: $(shell find ./login-frontend/src -type f)
	cd login-frontend && yarn && yarn build

setup-image: .setup-image
.setup-image: scripts/setup.Containerfile scripts/setup.sh
	podman build -t $(SETUP_IMAGE) -f scripts/setup.Containerfile .
	touch .setup-image


demo-image: .demo-image
.demo-image: scripts/demo.Containerfile demo-project/index.js $(shell find ./demo-project/demo-frontend)
	podman build -t $(DEMO_IMAGE):latest -f scripts/demo.Containerfile .
	touch .demo-image

demo-project/index.js: demo-project/main.ts 
	cd demo-project && yarn && yarn build