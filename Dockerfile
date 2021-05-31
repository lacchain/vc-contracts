FROM node:12.4
WORKDIR /app
COPY ./package*.json ./
COPY ./truffle-config.default ./truffle-config.js
RUN npm ci
COPY ./contracts ./contracts
COPY ./migrations ./migrations
COPY ./test ./test
CMD ["npm", "test"]