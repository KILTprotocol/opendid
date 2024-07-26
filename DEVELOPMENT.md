## Run OpenDID without Docker

To run the OpenDID locally,

1. Run the setup or add your `config.yaml` file with your seed.

```bash
ENDPOINT=peregrine ./scripts/setup.sh "insert your seed here"

```

1. Change the base path in the `config.yaml` to

```
basePath: ./login-frontend/dist
```

2. Build the frontend

```bash
cd login-frontend && yarn && yarn build && cd ..
```

3. Run the OpenDID Service

```bash
 cargo run --release --bin=opendid_peregrine --features=peregrine -- --config config.yaml
```

4. In a different terminal, run the demo project.

```bash
cd demo-project && yarn && yarn build && node index.js
```

## Release Process

Development Release: A release is triggered automatically when a pull request is merged into the `develop` branch. This release will deploy the application as the development version of OpenDID.
Production Release: A production release is triggered manually by specifying the release version (e.g., 1.0.0).

