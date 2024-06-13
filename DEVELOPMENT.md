## Run OpenDID without Docker

To run the OpenDID locally,

1. Run the setup or add your `config.yaml` file with your seed.

```bash
ENDPOINT=peregrine ./scripts/setup.sh "build hill second flame trigger simple rigid cabbage phrase evolve final eight"

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

Releasing if trigged when a PR is merged to the `main` branch.
TODO: Explain what version and tags need to be changed before a release.
