APP_NAME=opendid
MAIN_IMAGE="docker.io/kiltprotocol/$(APP_NAME)"
SETUP_IMAGE="docker.io/kiltprotocol/$(APP_NAME)-setup"
DEMO_IMAGE="docker.io/kiltprotocol/$(APP_NAME)-demo"

all: images

images: main-image setup-image demo-image

setup: config.yaml
config.yaml: setup-image
	docker run --rm -it -v $(shell pwd):/data $(SETUP_IMAGE) $(PAYMENT_SEED)

delete-did: opendid-setup-image
	docker run --rm -it -v $(shell pwd):/data -w /data --entrypoint /bin/bash $(SETUP_IMAGE) /app/scripts/delete-did.sh $(PAYMENT_SEED)

main-image: .main-image
.main-image: scripts/Dockerfile
	docker build -t $(MAIN_IMAGE):latest -f scripts/Dockerfile .
	touch .main-image

setup-image: .setup-image
.setup-image: scripts/setup.Dockerfile scripts/setup.sh
	docker build -t $(SETUP_IMAGE):latest -f scripts/setup.Dockerfile .
	touch .setup-image


demo-image: .demo-image
.demo-image: scripts/demo.Dockerfile
	docker build -t $(DEMO_IMAGE):latest -f scripts/demo.Dockerfile .
	touch .demo-image

push-dev-images: .main-image .setup-image .demo-image
	skopeo copy containers-storage:$(MAIN_IMAGE):latest docker://$(MAIN_IMAGE):dev
	skopeo copy containers-storage:$(SETUP_IMAGE):latest docker://$(SETUP_IMAGE):dev
	skopeo copy containers-storage:$(DEMO_IMAGE):latest docker://$(DEMO_IMAGE):dev
