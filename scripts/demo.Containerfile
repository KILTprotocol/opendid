FROM node

WORKDIR /srv
COPY ./demo-project/package.json ./package.json
COPY ./demo-project/main.ts ./main.ts
COPY ./demo-project/demo-frontend ./demo-frontend
RUN yarn && yarn build

ENTRYPOINT [ "/usr/local/bin/node", "/srv/index.js" ]