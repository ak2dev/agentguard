FROM node:22@sha256:ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12
RUN --mount=type=secret,id=npmrc,target=/root/.npmrc npm ci
USER node
