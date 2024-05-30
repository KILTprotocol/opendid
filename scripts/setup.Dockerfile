FROM docker.io/library/node:21-bookworm

WORKDIR /app
RUN apt update && apt install -y openssl jq
COPY scripts ./scripts
RUN cd /app/scripts/gen-did && yarn install

# for output data
VOLUME /data

ENTRYPOINT [ "/bin/bash", "/app/scripts/setup.sh" ]
