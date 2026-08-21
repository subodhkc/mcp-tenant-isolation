FROM node:22-slim AS builder

WORKDIR /build

COPY package.json package-lock.json ./
RUN npm ci

COPY tsconfig.json ./
COPY src/ ./src/
COPY schemas/ ./schemas/

RUN npm run build

FROM node:22-slim

WORKDIR /app

COPY --from=builder /build/package.json /build/package-lock.json ./
COPY --from=builder /build/dist/ ./dist/
COPY --from=builder /build/schemas/ ./schemas/

RUN npm ci --omit=dev

ENTRYPOINT ["node", "dist/cli/index.js"]
CMD ["--help"]
