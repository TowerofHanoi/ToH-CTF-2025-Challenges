FROM node:18

WORKDIR /app

COPY package.json ./
COPY yarn.lock ./
RUN yarn install
COPY . ./
RUN yarn build

ENTRYPOINT [ "node", "build" ]