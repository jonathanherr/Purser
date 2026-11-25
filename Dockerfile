FROM node:22-slim
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm install --no-save tsx
COPY migrations ./migrations
COPY src ./src
COPY tsconfig.json ./
USER node
EXPOSE 8787
CMD ["npx", "tsx", "src/index.ts"]
