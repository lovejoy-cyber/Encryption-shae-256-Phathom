# Built with repo root as context (see docker-compose.yml) so npm workspace
# links to packages/crypto-core resolve correctly.
#
# Runs via tsx rather than a separate `tsc` compile step: @phantomvault/crypto-core
# is consumed as TS source directly (see its package.json `main`), the same way
# every backend test in this repo already exercises it — one execution path,
# not a compiled-JS path that diverges from what's actually been tested.
FROM node:26-alpine AS base
WORKDIR /repo

FROM base AS deps
COPY package.json package-lock.json ./
COPY packages/crypto-core/package.json packages/crypto-core/package.json
COPY backend/package.json backend/package.json
RUN npm ci --workspace=@phantomvault/crypto-core --workspace=@phantomvault/backend

FROM deps AS runtime
ENV NODE_ENV=production
COPY packages/crypto-core packages/crypto-core
COPY backend backend

EXPOSE 3000
CMD ["npx", "tsx", "backend/src/server.ts"]
