FROM docker.io/library/node AS builder
WORKDIR /app
RUN apt update && apt install -y openssl jq
COPY scripts ./scripts
RUN cd /app/scripts/gen-did && npm install && npm run build

FROM docker.io/library/node
WORKDIR /app
RUN apt update && apt install -y openssl jq
COPY --from=builder /app/scripts/gen-did /app/scripts/gen-did
COPY --from=builder /app/scripts/gen-test-account /app/scripts/gen-test-account
COPY --from=builder /app/scripts/setup.sh /app/scripts/setup.sh

# for output data
VOLUME /data

ENTRYPOINT [ "/bin/bash", "scripts/setup.sh" ]
