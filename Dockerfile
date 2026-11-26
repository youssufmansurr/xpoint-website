FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev
COPY . .
ENV NODE_ENV=production DATA_DIR=/app/data UPLOAD_DIR=/app/uploads
EXPOSE 3000
CMD ["node", "server.js"]
