FROM docker.io/library/node

COPY example-frontend /app/example-frontend
RUN cd /app/example-frontend && npm install
WORKDIR /app/example-frontend

ENTRYPOINT [ "npm", "run", "start" ]