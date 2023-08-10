FROM quay.io/trusch/kiltctl:latest as kiltctl

FROM docker.io/library/node

WORKDIR /app
RUN apt update && apt install -y openssl jq
COPY --from=kiltctl /usr/local/bin/kiltctl /usr/local/bin/kiltctl
COPY scripts ./scripts
RUN cd /app/scripts/gen-key && npm install

# for output data
VOLUME /data

ENTRYPOINT [ "/bin/bash", "/app/scripts/setup.sh" ]