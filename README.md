# Simple Auth Relay App

This is a service to authenticate users using their DID and Verifiable-Credentials and generate JWT tokens from it.
It therefore acts as a bridge between the decentralized identity world and the centralized authentication world.
The resulting tokens can be used with any service that supports JWT tokens.

## Usage

### Prerequisites

- a KILT account with at least 3 KILT tokens
- an identity wallet like [Sporran](https://www.sporran.org/)
- a DID with a Verifiable Credential for testing from for example [SocialKYC](https://socialkyc.io)
- a laptop or desktop computer with a container engine like podman or docker installed

If you want to install podman on your machine (which I would recommend), you can [follow the instructions](https://podman.io/getting-started/installation).
If you have docker and want to stick with it, you can just replace every occurence of `podman` with `docker` in the following instructions.

### Generate the config file

In order to run the service we need to configure it to supply all needed keys and identifiers.
For this we will first generate a fresh DID for the service deployment and then derive a config file from it.

```bash
SEED="dont try this seed its completely made up for this nice example"
podman run --rm -it -v $(pwd):/data quay.io/kilt/simple-auth-relay-app-setup:latest "${SEED}"
```

The command will first generate a set of new mnemonics and then derive a DID from it.
All public and private keys will be stored in the `did-secrets.json` file.
Make a backup of this file!
If you lose it, you will lose access to your DID.
The `config.yaml` file will contain all the information needed to run the service including the private keys it needs to operate.
Note that this doesn't include the authentication key for the DID, so even if someone gets access to the config file, they can't steal your DID.
What they could do is writing wrong attestations to the blockchain, so make sure to also keep the config file safe.
In production you should place it in a secure location and only give read access to the user running the service.

### Run the service

Now that we have the config file, we can run the service. For this we will use the `simple-auth-relay-app` docker image.

```bash
podman run -d --rm \
    -v $(pwd)/config.yaml:/app/config.yaml \
    -p 3001:3001 \
    quay.io/kilt/simple-auth-relay-app:latest
```

Now you can visit http://localhost:3001/ and see the login page.
You can use the DID from your wallet to login.
If you don't have a DID yet, you can create one with [Sporran](https://www.sporran.org/).

### Integrate the service into your application

The service implements the [OpenID-Connect implicit flow](https://openid.net/specs/openid-connect-implicit-1_0.html#ImplicitFlow), therefore it is very simple to integrate.
All you have to do is to redirect the user to the login page and then handle the redirect back to your application.
The redirect will contain a JWT token in the URL. You can use this token to authenticate the user in your application.
The token will contain the DID of the user and the claims from the Verifiable Credential that was used to authenticate the user.
You can use this information to check if the user is allowed to access your application.

#### Example

The example code at [demo-project](./demo-project/) contains a minimal application which uses login via the simple-auth-relay-app. It is a simple [express](https://expressjs.com) application which exposes three things:

* a login page which handles the dispatching of the user to the simple-auth-relay-app
* a callback page for the openid connect flow to accept the token
* a protected resource which can only be accessed by authenticated users

If you wish to run this preconfigured demo application you can do it like this:

```bash
podman run -it -d --rm \
    --name demo-frontend \
    -p 1606:1606 \
    quay.io/kilt/simple-auth-relay-app-demo
```

You can now go to [http://localhost:1606/login.html](http://localhost:1606/login.html) to see a login page from the demo application.
When you click on login, you will be redirected to the simple-auth-relay-app login screen where you authenticate using your wallet.
After success you will be redirected back to the application and the token will be used to access a protected resource.

### Cleanup and delete the DID

If you want to delete the DID you generated earlier, you can use the `simple-auth-relay-app-setup` image again.
It will use the authentication key from the `did-secrets.json` file to delete the DID from the blockchain. 

```bash
SEED="dont try this seed its completely made up for this nice example"
podman run --rm -it \
    -v $(pwd):/data -w /data \
    --entrypoint /bin/bash \
    quay.io/kilt/simple-auth-relay-app-setup:latest \
        /app/scripts/delete-did.sh "${SEED}"
```

### Use dynamic client management

In case you want to dynamically create or remove OpenID Connect clients, you can configure the service to get its configuration from an [etcd cluster](https://etcd.io).
To do so all you need is to configure the connection parameters for the etcd cluster in the `config.yaml` file.

```yaml
...
etcd:
  endpoints: ["localhost:2379"]
  user: etcd-user
  password: my-password
  tlsDomainName: my.etcd.cluster.com
  tlsCaCert: >
    -----BEGIN CERTIFICATE-----
    <ca certificate data>
    -----END CERTIFICATE-----
  tlsClientCert: >
    -----BEGIN CERTIFICATE-----
    <client certificate data>
    -----END CERTIFICATE-----
  tlsClientKey: >
    -----BEGIN RSA PRIVATE KEY-----
    <client key data>
    -----END RSA PRIVATE KEY-----
...
```

All fields except `endpoints` are optional and depending on your etcd setup you might not need them.
When everything is setup you can start putting client configurations into the etcd cluster.

```bash
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
```

If you want to quickly try this out you can first generate a config using the setup image as described above, add the etcd configuration and then start the service using the example script in [./scripts/start-demo-etcd.sh](./scripts/start-demo-etcd.sh).