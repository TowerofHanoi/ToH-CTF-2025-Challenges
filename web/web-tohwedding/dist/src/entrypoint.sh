#!/bin/sh
SECRET=$(openssl rand -hex 16)

export RSVP_PATH=rsvp_$SECRET.csv

mv /var/www/html/rsvp_X.csv /var/www/html/$RSVP_PATH

exec "$@"
