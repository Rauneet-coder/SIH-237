FROM node:20-alpine AS base

WORKDIR /app

# Install production dependencies
COPY package*.json ./
RUN npm ci --only=production

# Copy source code
COPY . .

# Run as non-root node user
USER node

EXPOSE 8000

ENV PORT=8000 \
    NODE_ENV=production

CMD ["node", "src/server.js"]
