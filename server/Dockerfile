FROM node:22-alpine
WORKDIR /app
COPY package.json *.mjs ./
COPY seeds ./seeds
RUN mkdir /data && chown node:node /data
USER node
ENV SENTINEL_DATA_DIR=/data SENTINEL_BIND=0.0.0.0 PORT=8787
EXPOSE 8787
VOLUME /data
CMD ["node", "cli.mjs", "serve"]
