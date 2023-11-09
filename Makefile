APP_NAME=opendid
MAIN_IMAGE="docker.io/kiltprotocol/$(APP_NAME)"
SETUP_IMAGE="docker.io/kiltprotocol/$(APP_NAME)-setup"
DEMO_IMAGE="docker.io/kiltprotocol/$(APP_NAME)-demo"

all: images

images: main-image setup-image demo-image

setup: config.yaml
config.yaml: setup-image
	podman run --rm -it -v $(shell pwd):/data $(SETUP_IMAGE) $(PAYMENT_SEED)

delete-did: opendid-setup-image
	podman run --rm -it -v $(shell pwd):/data -w /data --entrypoint /bin/bash $(SETUP_IMAGE) /app/scripts/delete-did.sh $(PAYMENT_SEED)

main-image: .main-image
.main-image: scripts/Containerfile
	podman build -t $(MAIN_IMAGE):latest -f scripts/Containerfile .
	touch .main-image

setup-image: .setup-image
.setup-image: scripts/setup.Containerfile scripts/setup.sh $(shell find ./scripts -name "*.ts" -not -path "*/node_modules/*")
	podman build -t $(SETUP_IMAGE):latest -f scripts/setup.Containerfile .
	touch .setup-image

demo-image: .demo-image
.demo-image: scripts/demo.Containerfile
	podman build -t $(DEMO_IMAGE):latest -f scripts/demo.Containerfile .
	touch .demo-image

push-dev-images: .main-image .setup-image .demo-image
	skopeo copy containers-storage:$(MAIN_IMAGE):latest docker://$(MAIN_IMAGE):dev
	skopeo copy containers-storage:$(SETUP_IMAGE):latest docker://$(SETUP_IMAGE):dev
	skopeo copy containers-storage:$(DEMO_IMAGE):latest docker://$(DEMO_IMAGE):dev
