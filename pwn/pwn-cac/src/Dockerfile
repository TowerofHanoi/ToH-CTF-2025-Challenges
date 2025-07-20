FROM ubuntu@sha256:5d070ad5f7fe63623cbb99b4fc0fd997f5591303d4b03ccce50f403957d0ddc4

ENV DEBIAN_FRONTEND noninteractive

RUN apt update && apt install -y socat

WORKDIR /app

COPY ./cac .
COPY ./flag.txt .


RUN chmod +x cac

RUN chown -R root:root /app/*
RUN chmod -R o-w /app/*
RUN chown -R root:root /app/flag.txt
RUN chmod -R o-w /app/flag.txt

RUN useradd ctf
USER ctf

ENTRYPOINT socat TCP4-LISTEN:2727,fork,reuseaddr EXEC:/app/cac


