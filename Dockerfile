FROM node:20-alpine

WORKDIR /app

COPY package*.json ./
RUN npm install --omit=dev

COPY . .

# Render injects PORT dynamically
EXPOSE 10000

CMD ["node", "server.js"]
