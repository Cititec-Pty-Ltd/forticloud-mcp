# Multi-stage build for efficient container size
FROM node:22-alpine AS builder

ARG VERSION="unknown"
ARG COMMIT_SHA="unknown"
ARG BUILD_DATE="unknown"

WORKDIR /app

COPY package*.json ./
RUN npm ci --ignore-scripts

COPY . .
RUN npm run build
RUN npm prune --omit=dev

FROM node:22-alpine AS production

RUN apk -U upgrade --no-cache

RUN addgroup -g 1001 -S mcp && \
    adduser -S mcp -u 1001 -G mcp

WORKDIR /app

COPY --from=builder /app/package.json ./
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules

RUN chown -R mcp:mcp /app

# Remove bundled npm/npx from the runtime image - not needed at runtime; CMD
# runs node directly, and this trims a class of Trivy findings against npm's
# own bundled dependencies in the base image.
RUN rm -rf /usr/local/lib/node_modules/npm /usr/local/bin/npm /usr/local/bin/npx

USER mcp

# stdio only: the Cititec MCP host runs one container per connection
# (docker run --rm -i) with the service's env file
# (FORTICLOUD_API_ID, FORTICLOUD_API_PASSWORD, optional FORTICLOUD_* URLs and client IDs). There is no HTTP listener.
ENV NODE_ENV=production
ENV LOG_LEVEL=info
ENV MCP_TRANSPORT=stdio

CMD ["node", "dist/index.js"]

ARG VERSION="unknown"
ARG COMMIT_SHA="unknown"
ARG BUILD_DATE="unknown"

LABEL version="${VERSION}"
LABEL description="FortiCloud MCP Server - Model Context Protocol server for Fortinet FortiCloud"
LABEL org.opencontainers.image.title="forticloud-mcp"
LABEL org.opencontainers.image.description="Model Context Protocol server for Fortinet FortiCloud (Asset Management and FortiGate Cloud, read-only)"
LABEL org.opencontainers.image.version="${VERSION}"
LABEL org.opencontainers.image.created="${BUILD_DATE}"
LABEL org.opencontainers.image.revision="${COMMIT_SHA}"
LABEL org.opencontainers.image.source="https://github.com/Cititec-Pty-Ltd/forticloud-mcp"
LABEL org.opencontainers.image.vendor="Cititec Pty Ltd"
LABEL org.opencontainers.image.licenses="Apache-2.0"
