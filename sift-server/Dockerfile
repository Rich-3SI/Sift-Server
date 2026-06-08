# Sift Server — MCP security firewall.
#
# Build: docker build -f sift-server/Dockerfile -t sift-server:latest .
# Run:   docker run -p 8080:8080 \
#          -v /etc/sift-server/config.json:/etc/sift-server/config.json \
#          -e SIFT_ADMIN_SECRET=... \
#          sift-server:latest
# Map 8081 only when server.adminHost is explicitly set for a trusted network.
#
# IMPORTANT: the build context must be the REPO ROOT because sift-server's
# source imports from ../src/*. Use `-f sift-server/Dockerfile .` from root.

FROM node:22-alpine AS build
WORKDIR /build

# Copy core sources that sift-server imports from plus the sift-server package.
COPY package.json package-lock.json* ./
COPY tsconfig.json ./
COPY scripts/add-shebang.mjs ./scripts/add-shebang.mjs
COPY src ./src
COPY sift-server ./sift-server

# Install core deps, including TypeScript for the sift-server build. Lifecycle
# scripts are skipped because the root package's prepare script runs `tsc`
# before dev dependencies would be available in an --omit=dev install.
RUN npm ci --ignore-scripts || npm install --ignore-scripts

# Install sift-server deps + typescript for the build, then compile.
WORKDIR /build/sift-server
RUN npm ci --ignore-scripts
RUN npm run build
RUN npm prune --omit=dev --ignore-scripts

WORKDIR /build
RUN npm prune --omit=dev --ignore-scripts

# ── Runtime image ──────────────────────────────────────────────────────────
FROM node:22-alpine AS runtime
WORKDIR /app

ENV NODE_ENV=production

# Copy only what we need at runtime.
COPY --from=build /build/sift-server/package.json ./sift-server/package.json
COPY --from=build /build/sift-server/dist ./sift-server/dist
COPY --from=build /build/sift-server/node_modules ./sift-server/node_modules
COPY --from=build /build/node_modules ./node_modules

RUN mkdir -p /data /etc/sift-server && chown -R node:node /data

EXPOSE 8080 8081

# Default config path — mount your config as a volume at this path.
ENV SIFT_SERVER_CONFIG=/etc/sift-server/config.json

USER node
CMD ["node", "sift-server/dist/sift-server/src/index.js", "--config", "/etc/sift-server/config.json"]
