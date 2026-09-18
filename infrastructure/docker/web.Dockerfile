# syntax=docker/dockerfile:1
# Production Dockerfile for SentinelForge Web Frontend
# Hardened unprivileged non-root execution, minimal attack surface

FROM node:20-alpine AS runner
WORKDIR /app

ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1
ENV PORT=3000
ENV HOSTNAME="0.0.0.0"

# Create dedicated non-root unprivileged service user and group
RUN addgroup --system --gid 1001 nodejs && \
    adduser --system --uid 1001 nextjs

# Set correct permissions for prerender cache
RUN mkdir -p .next && chown nextjs:nodejs .next

# Leverage output traces to run standalone Next.js production server
COPY --chown=nextjs:nodejs apps/web/public ./public
COPY --chown=nextjs:nodejs apps/web/.next/standalone ./
COPY --chown=nextjs:nodejs apps/web/.next/static ./.next/static

USER nextjs

EXPOSE 3000

HEALTHCHECK --interval=10s --timeout=5s --start-period=10s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://127.0.0.1:3000/ || exit 1

CMD ["node", "server.js"]
