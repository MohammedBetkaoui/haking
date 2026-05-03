FROM node:20-alpine

WORKDIR /app

COPY package*.json ./
RUN npm ci --omit=dev

COPY src ./src
COPY .env.example ./

RUN mkdir -p /app/generated-reports

EXPOSE 4000

CMD ["npm", "start"]