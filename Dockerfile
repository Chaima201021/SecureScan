FROM node:20-bookworm-slim

WORKDIR /app

RUN apt-get update \
  && apt-get install -y --no-install-recommends nmap ca-certificates \
  && rm -rf /var/lib/apt/lists/*

COPY backend/package*.json ./backend/
RUN npm --prefix backend ci --omit=dev

COPY . .

RUN mkdir -p /app/backend/data

ENV NODE_ENV=production
ENV PORT=3000

EXPOSE 3000

CMD ["npm", "--prefix", "backend", "start"]
