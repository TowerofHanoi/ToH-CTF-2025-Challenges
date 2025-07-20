FROM python:slim

RUN pip install flask && \
    apt-get update && apt-get install -y sqlite3

RUN groupadd -r rollback && useradd -r -g rollback rollback && \
    mkdir /app

COPY app.py /app/
COPY templates /app/templates/
COPY flag.txt /flag.txt
COPY init.sql /tmp/init.sql


RUN chmod 444 /flag.txt && \
    chmod -R 555 /app/templates && \
    chown rollback:rollback /app

USER rollback

RUN sqlite3 /app/database.sqlite < /tmp/init.sql && \
    mkdir /app/uploads

WORKDIR /app
EXPOSE 5000

CMD ["python", "/app/app.py"]