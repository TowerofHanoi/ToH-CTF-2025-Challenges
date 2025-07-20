default:
	mkdir -p release
	cd src ; rsync -a --filter=":- .gitignore" frontend src .gitignore .dockerignore Cargo.* Caddyfile docker-compose.yml Dockerfile ../release/
	cp README.md release/
	echo 'REDACTED' > release/flag.txt
#	tar cpzf web-rusty-rest-shop.tgz release/

clean: reset
	rm release/ -rf

up: default
	cd release; docker compose up --build

reset:
	cd release; docker compose down
	cd release; docker compose rm -svf
	rm -f release/db/db.sqlite3

package: default
	tar cpzf web-rusty-rest-shop.tar.gz -C release/ \
          --exclude target/ --exclude flag.txt --exclude db/ .
