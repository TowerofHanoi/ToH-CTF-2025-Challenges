FROM ghcr.io/puppeteer/puppeteer:24.13.0

WORKDIR /app

USER root
COPY ./chall/bot.js /app/bot.js
COPY ./chall/package.json /app/package.json

RUN chown -R pptruser:pptruser /app
USER pptruser

RUN npm install

EXPOSE 3001
CMD ["node", "bot.js"]
