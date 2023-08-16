# dauth

`dauth` is a service to authenticate users using their DID and Verifiable-Credentials and generate JWT tokens from it.
It therefore acts as a bridge between the decentralized identity world and the centralized authentication world. The resulting tokens can be used with any service that supports JWT tokens.

## Usage

### Prerequisites

- a KILT account with at least 3 KILT tokens
- an identity wallet like [Sporran](https://www.sporran.org/)
- a DID with a Verifiable Credential for testing the login
- a laptop or desktop computer with a container engine like podman or docker installed

If you want to install podman on your machine (which I would recommend), you can follow the instructions [here](https://podman.io/getting-started/installation). If you have docker and want to stick with it, you can just replace every occurence of `podman` with `docker` in the following instructions.

### Generate the config file

In order to run the service we need to configure it to supply all needed keys and identifiers.
For this we will first generate a fresh DID for the service deployment and then derive a config file from it.

```bash
SEED="dont try this seed its completely made up for this nice example"
podman run --rm -it -v $(pwd):/data quay.io/kilt/dauth-setup:latest "${SEED}"
```

The command will first generate a set of new mnemonics and then derive a DID from it. All public and private keys will be stored in the `did-secrets.json` file. Make a backup of this file! If you lose it, you will lose access to your DID. The `config.yaml` file will contain all the information needed to run the service including the private keys it needs to operate. Note that this doesn't include the authentication key for the DID, so even if someone gets access to the config file, they can't steal your DID. What they could do is writing wrong attestations to the blockchain, so make sure to also keep the config file safe. In production you should place it in a secure location and only give read access to the user running the service.

### Run the service

Now that we have the config file, we can run the service. For this we will use the `dauth` docker image.

```bash
podman run --rm -it -v $(pwd)/config.yaml:/app/config.yaml -p 3001:3001 quay.io/kilt/dauth:latest
```

Now you can visit http://localhost:3001/ and see the login page. You can use the DID you generated earlier to login. If you don't have a DID yet, you can create one with [Sporran](https://www.sporran.org/).

### Cleanup and delete the DID

If you want to delete the DID you generated earlier, you can use the `dauth-setup` image again.

```bash
podman run --rm -it \
    -v $(pwd):/data -w /data \
    --entrypoint /bin/bash \
    quay.io/kilt/dauth-setup:latest \
        /app/scripts/delete-did.sh "${PAYMENT_SEED}"
```
