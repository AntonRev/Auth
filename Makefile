# Run docker local
dockerlocal:
	docker-compose -f docker-compose.yaml -f docker-compose.override.yml up -d --build

# Start jaeger server
run jaeger:
	docker run -d -p6831:6831/udp -p16686:16686 jaegertracing/all-in-one:latest

# Stop all dockerfile
docker_stop:
	docker-compose stop jaeger nginx postgres flask redis

docker_del:
	docker-compose rm jaeger nginx postgres flask redis

# first migration
migration first:
	export FLASK_APP=app/app.py
	flask db init
	flask db migrate -m "Initial migration."
	flask db upgrade

# For local tests app
flask_local:
	docker-compose -f docker-compose.yaml -f docker-compose.override.yml up -d --build postgres redis
	export FLASK_APP=app/app.py
	flask db upgrade
	flask run