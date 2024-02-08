FROM docker.io/library/node

WORKDIR /app
RUN apt update && apt install -y openssl jq
COPY scripts ./scripts
RUN cd /app/scripts/gen-did && npm install

# for output data
VOLUME /data

ENTRYPOINT [ "/bin/bash", "/app/scripts/setup.sh" ]
