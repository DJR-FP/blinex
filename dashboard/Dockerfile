FROM node:20-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci

FROM node:20-alpine AS builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .

# Bake the API URL at build time (override with --build-arg in production)
ARG NEXT_PUBLIC_MGMT_API=http://localhost:8080
ENV NEXT_PUBLIC_MGMT_API=$NEXT_PUBLIC_MGMT_API

RUN npm run build

FROM node:20-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production

RUN addgroup -S meshnet && adduser -S meshnet -G meshnet

COPY --from=builder /app/.next/standalone ./
COPY --from=builder /app/.next/static ./.next/static
COPY --from=builder /app/public ./public

USER meshnet

EXPOSE 3000

ENV PORT=3000
ENV HOSTNAME=0.0.0.0

CMD ["node", "server.js"]
