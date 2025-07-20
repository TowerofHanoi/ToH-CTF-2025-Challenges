FROM ubuntu@sha256:b59d21599a2b151e23eea5f6602f4af4d7d31c4e236d22bf0b62b86d2e386b8f

ENV DEBIAN_FRONTEND noninteractive

RUN apt update && apt install -y socat

WORKDIR /app

COPY ./provola .
COPY ./flag.txt .


RUN chmod +x provola

RUN chown -R root:root /app/*
RUN chmod -R o-w /app/*
RUN chown -R root:root /app/flag.txt
RUN chmod -R o-w /app/flag.txt

RUN useradd ctf
USER ctf

ENTRYPOINT socat TCP4-LISTEN:2727,fork,reuseaddr EXEC:/app/provola