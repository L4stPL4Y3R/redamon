# Vulnerable Node.js server with node-serialize for CVE-2017-5941 testing
# WARNING: This is intentionally vulnerable - DO NOT use in production!

FROM node:8.17.0-slim

# Set unbuffered output for logging
ENV PYTHONUNBUFFERED=1
ENV NODE_ENV=production

WORKDIR /app

# Copy package files first for layer caching
COPY package.json ./

# Install dependencies (including vulnerable node-serialize 0.0.4)
RUN npm install --production 2>&1

# Copy application code
COPY server.js ./
COPY www/ ./www/

# Run as root so RCE gives root shell
# This is intentionally insecure for testing purposes

EXPOSE 3000

CMD ["node", "server.js"]
