FROM node:24.2.0

WORKDIR /app

USER root

COPY ./chall/public /app/public
COPY ./chall/server.js /app/server.js
COPY ./chall/package.json /app/package.json

RUN npm install

EXPOSE 3000
CMD ["node", "server.js"]
