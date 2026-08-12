FROM docker.io/library/node:24.11.1-bookworm-slim@sha256:44b49d6e2d23f6754fb084ef9d34ff14590343ad1ee168f8acf8f7bc9fccde2f

ARG SOURCE_COMMIT
RUN case "$SOURCE_COMMIT" in (*[!0-9a-f]*|"") exit 1;; esac && test "${#SOURCE_COMMIT}" = "40"
LABEL org.opencontainers.image.revision=$SOURCE_COMMIT

WORKDIR /app
ENV NODE_ENV=production

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates openssl && rm -rf /var/lib/apt/lists/*

COPY package.json package-lock.json ./
RUN npm ci --omit=dev

COPY bin ./bin
COPY src ./src
COPY prompts ./prompts

RUN mkdir -p /workspace && chown node:node /workspace
USER node

EXPOSE 8443
ENTRYPOINT ["node","bin/mechanics-proof-party.mjs"]
