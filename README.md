# OpenDID

OpenDID is a service that generates JWT tokens to authenticate users using the user’s [Decentralized Identifier (DID)](https://docs.kilt.io/docs/concepts/did) and Verifiable Credentials.
It acts as a bridge between the decentralized identity world and the centralized authentication world.
You can use the resulting tokens with any service that supports JWT tokens.

## Usage

### Prerequisites

-   a KILT account with at least 3 KILT Coins
-   an identity wallet like [Sporran](https://www.sporran.org/)
-   a DID with a Verifiable Credential for testing, for example, from [SocialKYC](https://socialkyc.io)
-   `podman` or `docker` installed

    If you want to install podman on your machine (which is recommended), you can [follow the instructions](https://podman.io/getting-started/installation).
    If you have docker and want to stick with it, replace every occurrence of `podman` with `docker` in the following instructions.

### Generate the config file

To run the service you need to create the configuration that contains all the needed keys and identifiers.
To do this, generate a fresh DID for the service deployment and then create a config file from it.

First assign your KILT account seed to a variable named `SEED` then run `opendid-setup` container.

`SEED="dont try this seed its completely made up for this nice example"`

If your account is on KILT Spiritnet, set `ENDPOINT="spiritnet"`; alternatively, if it is on the Peregrine Testnet, configure `ENDPOINT="peregrine"`.

```bash
docker run --rm -it -e "ENDPOINT=${ENDPOINT}" -v $(pwd):/data docker.io/kiltprotocol/opendid-setup:latest "${SEED}"
```

The command generates a set of new mnemonics and then derives a DID from it.
The DID requires a deposit of around 2 KILT.
All public and private keys are stored in the `did-secrets.json` file.
Make a backup of this file!
If you lose the file, you will lose access to your DID.
The `config.yaml` file contains all the information needed to run the service including private keys.
Note that this doesn't include the authentication key for the DID, so even if someone gets access to the config file, they can't steal your DID.
However, they could write untrue attestations to the blockchain, so make sure to also keep the config file safe.
In production, you need to place it in a secure location and only give read access to the user running the service.

### Run the service

Now that you have the config file, you can run the service. For this, use the `docker.io/kiltprotocol/opendid` docker image.

```bash
docker run -d --rm \
    -v $(pwd)/config.yaml:/app/config.yaml \
    -p 3001:3001 \
    docker.io/kiltprotocol/opendid:latest
```

Now you can open `http://localhost:3001` and see the login page, but don't login yet, there's one more step for the flow to work.

### Integrate the service into your application

A service needs to implement the [OpenID-Connect implicit flow](https://openid.net/specs/openid-connect-implicit-1_0.html#ImplicitFlow), which does the following:

-   Redirects the user to the login page and then handle the redirect back to your application.
-   The redirect contains a JWT token in the URL. You can use this token to authenticate the user in your application.
-   The token contains the DID of the user and the claims from the Verifiable Credential used to authenticate the user.
-   You can use this information to check if the user is allowed to access your application.

#### Example

The example code at [demo-project](./demo-project/) contains a minimal application that follows the flow above using opendid.
It's an [express](https://expressjs.com) application that exposes three things:

-   A login page that handles the dispatching of the user to the opendid
-   A callback page for the openid connect flow to accept the token
-   A protected resource that only authenticated users can access

Run the pre-configured demo application with the following command:

```bash
docker run -d -it --rm \
    --name demo-frontend \
    -p 1606:1606 \
    docker.io/kiltprotocol/opendid-demo
```

You can now open [http://localhost:1606/login.html](http://localhost:1606/login.html) to see a login page from the demo application.
When you click on login, the application redirects you to the opendid login screen where you authenticate using a DID from your wallet.
After success, the service redirects you back to the application and uses the token to access a protected resource.

If you don't have a DID yet, you can create one with [Sporran](https://www.sporran.org/).

### Cleanup and delete the DID

If you want to delete the DID you generated earlier, you can use the `opendid-setup` image again.
This uses the authentication key from the `did-secrets.json` file to delete the DID from the blockchain.
(If you delete your DID, your deposit is returned.)

```bash
SEED="dont try this seed its completely made up for this nice example"
docker run --rm -it \
    -v $(pwd):/data -w /data \
    --entrypoint /bin/bash \
    docker.io/kiltprotocol/opendid-setup:latest \
        /app/scripts/delete-did.sh "${SEED}"
```

## Advanced usage

### Use dynamic client management

If you want to dynamically create or remove OpenID Connect clients, you can configure the service to get its configuration from an [etcd cluster](https://etcd.io).
To do so, configure the connection parameters for the etcd cluster in the `config.yaml` file.

```yaml
---
etcd:
    endpoints: ["localhost:2379"]
    user: etcd-user
    password: my-password
    tlsDomainName: my.etcd.cluster.example.com
    tlsCaCert: |
        -----BEGIN CERTIFICATE-----
        <ca certificate data>
        -----END CERTIFICATE-----
    tlsClientCert: |
        -----BEGIN CERTIFICATE-----
        <client certificate data>
        -----END CERTIFICATE-----
    tlsClientKey: |
        -----BEGIN RSA PRIVATE KEY-----
        <client key data>
        -----END RSA PRIVATE KEY-----
```

All fields except `endpoints` are optional and depending on your etcd setup you might not need them.
When everything is set up you can start putting client configurations into the etcd cluster.

```bash
CLIENT_SPEC=$(cat <<EOF
{
  "requirements": [{
    "cTypeHash":"0x3291bb126e33b4862d421bfaa1d2f272e6cdfc4f96658988fbcffea8914bd9ac",
    "trustedAttesters": [
    "did:kilt:4pehddkhEanexVTTzWAtrrfo2R7xPnePpuiJLC7shQU894aY",
    "did:kilt:4pnfkRn5UurBJTW92d9TaVLR2CqJdY4z5HPjrEbpGyBykare"
    ],
    "requiredProperties": ["Email"]
  }],
  "redirectUrls": ["http://localhost:1606/callback.html"]
}
EOF
)
CLIENT_SPEC=$(echo $CLIENT_SPEC | jq -c)
etcdctl put /opendid/clients/new-client "${CLIENT_SPEC}"
```

If you want to try this out you can first generate a config using the setup image as described above, add the etcd configuration and then start the service using the example script in [./scripts/start-demo-etcd.sh](./scripts/start-demo-etcd.sh).

### Add advanced claim checks using RHAI scripts

To add custom checks that are executed on the claims of the Verifiable Credential, you can use [Rhai](https://rhai.rs) scripts.
To try it out you have to add a `checksDirectory` entry to the client configuration in the `config.yaml` file.

Example:

```yaml
---
clients:
    example-client:
        requirements:
            - cTypeHash: "0x3291bb126e33b4862d421bfaa1d2f272e6cdfc4f96658988fbcffea8914bd9ac"
              trustedAttesters:
                  [
                      "did:kilt:4pehddkhEanexVTTzWAtrrfo2R7xPnePpuiJLC7shQU894aY",
                      "did:kilt:4pnfkRn5UurBJTW92d9TaVLR2CqJdY4z5HPjrEbpGyBykare",
                  ]
              requiredProperties: ["Email"]
        redirectUrls:
            - http://localhost:1606/callback.html
        checksDirectory: /app/checks
```

Now create a directory `checks` in the same directory as the `config.yaml` file and add a file `example-check.rhai` with the following content:

```rust
// This is a simple example of a login policy that allows only users with an email address ending with `kilt.io` to login.

let SUFFIX = "kilt.io";

// ID_TOKEN contains the id_token as to be send to the user from the OIDC provider
let token = parse_id_token(ID_TOKEN);

// We can inspect the token and especially the `pro` sub-object that contains the users claims
if token.pro.Email.ends_with(SUFFIX) {
  // The user is allowed to login
  return true;
}

// The user is not allowed to login
return false;
```

You can now start the service bind-mounting the script and try it out. If you wish to execute the service on the Peregrine runtime, you must modify the environment variable RUNTIME to "peregrine".

```bash
docker run -d --rm \
    -v $(pwd)/config.yaml:/app/config.yaml \
    -v $(pwd)/checks:/app/checks \
    -e RUNTIME=spiritnet \
    -p 3001:3001 \
    docker.io/kiltprotocol/opendid:latest
```

When you now log in with a user that has an email address ending with `kilt.io` the service allows you to log in.
If you use a different email address, the service denies you access.
