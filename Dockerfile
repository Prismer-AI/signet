FROM node:24-slim

WORKDIR /app

COPY package.json package-lock.json ./
COPY packages ./packages
COPY examples/mcp-agent ./examples/mcp-agent

RUN npm ci
RUN npm run build --workspace @signet-auth/core
RUN npm run build --workspace @signet-auth/mcp
RUN npm run build --workspace @signet-auth/mcp-server

WORKDIR /app/examples/mcp-agent

RUN npm ci

ENV SIGNET_REQUIRE_SIGNATURE=false
ENV SIGNET_MAX_AGE=300

CMD ["npm", "run", "verifier-server"]
