# Use the official Node.js image as the base image
FROM node:18
ENV DEBIAN_FRONTEND=noninteractive
ENV PROFILE_PATH=/home/user/firefox-profile

# Install Selenium and Firefox dependencies
RUN apt-get update && apt-get install -y \
  firefox-esr \
  libnss3 \
  libxss1 \
  libasound2 \
  fonts-liberation \
  libappindicator3-1 \
  xdg-utils \
  packagekit-gtk3-module \
  gnupg2 \
  wget \
  ca-certificates \
  xvfb \
  libgbm1 \
  libxrandr2 \
  libpangocairo-1.0-0 \
  libatk1.0-0 \
  libcairo-gobject2 \
  libgtk-3-0 \
  libgdk-pixbuf2.0-0 \
  && rm -rf /var/lib/apt/lists/*

# Create /bot directory
RUN mkdir /home/user

# Set the working directory inside the container
WORKDIR /home/user

# Copy package.json and package-lock.json to the working directory
COPY package*.json ./

# Install dependencies
RUN npm install && npx playwright install firefox

# Copy the rest of the application code to the working directory
COPY *.js ./
COPY ./firefox-profile /home/user/firefox-profile

# Expose the port the app runs on
EXPOSE 5001

# Start the application
CMD ["node", "app.js"]