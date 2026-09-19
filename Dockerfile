FROM node:22-slim
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci --omit=dev
RUN npm install --save-dev @types/node@20.11.0
COPY src/ ./src/
COPY tsconfig.json ./
RUN ./node_modules/.bin/tsc
ENV NODE_ENV=production
ENV PORT=8080
ENV FACILITATOR_URL=https://x402.org/facilitator
EXPOSE 8080
CMD ["node", "dist/index.js"]
