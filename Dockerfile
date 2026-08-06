FROM node:20-slim AS builder

WORKDIR /build

COPY package.json package-lock.json ./
RUN npm ci

COPY tsconfig.json ./
COPY src/ ./src/
COPY schemas/ ./schemas/

RUN npm run build

FROM node:20-slim

RUN npm install -g mcp-tenant-isolation@1.6.1 || true

COPY --from=builder /build/dist/ ./dist/
COPY package.json ./

RUN npm install --omit=dev

ENTRYPOINT ["node", "dist/cli/index.js"]
CMD ["--help"]
