FROM node:20-slim
ENV NODE_ENV=production
WORKDIR /app
COPY package.json package-lock.json* /app/
RUN npm install --omit=dev
COPY . /app
EXPOSE 8080
CMD ["npm","start"]
