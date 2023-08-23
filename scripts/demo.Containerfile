FROM node:alpine

WORKDIR /srv
COPY ./demo-project/package.json ./package.json
COPY ./demo-project/node_modules ./node_modules
COPY ./demo-project/index.js ./index.js
COPY ./demo-project/demo-frontend ./demo-frontend

ENTRYPOINT [ "/usr/local/bin/node", "/srv/index.js" ]