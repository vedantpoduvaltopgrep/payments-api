# Build in a full image, run in a slim one. bcrypt has a native addon, so the
# builder needs a toolchain the runtime does not.
FROM node:20.11-bookworm AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev
COPY src ./src

FROM node:20.11-bookworm-slim AS runtime
ENV NODE_ENV=production
WORKDIR /app

RUN groupadd --system --gid 10001 aurora \
 && useradd --system --uid 10001 --gid aurora aurora

COPY --from=build --chown=aurora:aurora /app/node_modules ./node_modules
COPY --from=build --chown=aurora:aurora /app/src ./src
COPY --chown=aurora:aurora package.json ./
COPY --chown=aurora:aurora certs ./certs

USER aurora
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:8080/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "src/server.js"]
