FROM node:24.2.0

WORKDIR /app
COPY . .

RUN apt-get update && apt-get install -y \
    git \
    python3 \
    cmake \
    build-essential \
    wget \
    && rm -rf /var/lib/apt/lists/*
RUN git clone https://github.com/emscripten-core/emsdk.git /emsdk \
    && cd /emsdk \
    && ./emsdk install 1.39.0 \
    && ./emsdk activate 1.39.0

ENV PATH="/emsdk:/emsdk/node/12.9.1_64bit/bin:/emsdk/upstream/emscripten:${PATH}"
ENV EMSDK="/emsdk"
ENV EM_CONFIG="/emsdk/.emscripten"
ENV EMSCRIPTEN="/emsdk/upstream/emscripten"

RUN npm install --no-audit --no-fund
RUN npm run build

CMD ["npm", "run", "dev"]