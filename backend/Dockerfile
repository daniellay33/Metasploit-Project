FROM node:18-alpine

WORKDIR /app

RUN apk add --no-cache docker-cli

COPY package.json package-lock.json ./
RUN npm ci --omit=dev

COPY server.js ./

EXPOSE 3000

CMD ["node", "server.js"]
