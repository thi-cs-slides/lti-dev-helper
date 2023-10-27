FROM node:14-alpine

# Set work dir
WORKDIR /var/lib/app/

# Copy package.json and install depedencies
COPY package.json package-lock.json ./
RUN npm install

# Copy backend and frontend
COPY . .

# Expose port
EXPOSE 4000

CMD ["sh","-c","npm start"]