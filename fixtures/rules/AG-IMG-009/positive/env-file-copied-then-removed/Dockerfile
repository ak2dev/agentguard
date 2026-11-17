FROM node:22@sha256:ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12
COPY .env /app/.env
RUN npm ci && rm /app/.env
USER node
