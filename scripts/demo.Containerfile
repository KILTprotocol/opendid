FROM node:alpine as builder
WORKDIR /build

COPY demo-project /build/

RUN yarn && yarn build

FROM node:alpine

WORKDIR /srv
COPY --from=builder /build/package.json ./package.json
COPY --from=builder /build/node_modules ./node_modules
COPY --from=builder /build/index.js ./index.js
COPY --from=builder /build/demo-frontend ./demo-frontend

ENTRYPOINT [ "/usr/local/bin/node", "/srv/index.js" ]
