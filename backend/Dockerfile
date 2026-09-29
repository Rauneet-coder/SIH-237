FROM node:20-alpine AS base

WORKDIR /app

# Install production dependencies
COPY package*.json ./
RUN npm ci --only=production

# Copy source code
COPY . .

# Create writable storage directories before dropping to non-root
RUN mkdir -p /app/storage/encrypted /app/storage/key-agent-keystore \
    && chown -R node:node /app/storage

# Run as non-root node user
USER node

# Cloud Run injects its own PORT; default to 8000 for local docker runs
ENV PORT=8000 \
    NODE_ENV=production

EXPOSE 8000

CMD ["node", "src/server.js"]
