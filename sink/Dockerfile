# Parallax sink. Built remotely on Fly builders (no local Docker on the box).
FROM oven/bun:1.4-alpine
WORKDIR /app
COPY server.ts ./
COPY registry ./registry
ENV PORT=8080
EXPOSE 8080
CMD ["bun", "server.ts"]
