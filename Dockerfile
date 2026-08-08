FROM node:22-slim

WORKDIR /app
ENV NODE_ENV=production
ENV CLOCKCHAIN_FUNDING_PASSWORD_FILE=/app/keys/funding.password

COPY package.json package-lock.json ./
RUN npm ci --omit=dev

COPY bin ./bin
COPY src ./src
COPY prompts ./prompts

RUN mkdir -p /app/keys /app/runs && chown -R node:node /app/keys /app/runs

USER node
CMD ["node","bin/clockchain-host.mjs","--keystore","/app/keys/funding-wallet.json"]
