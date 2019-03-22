all: clean build_adapter docker_build docker_push
.PHONY: all 

clean:
	rm -rf bin
build_adapter: 
	CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -v -o bin/panpolicyenforcer ./panpolicyenforcer/cmd/

docker_build:
	docker build -t vinayvenkat/panpolicyenforcer:v1 .

docker_push:
	docker push vinayvenkat/panpolicyenforcer:v1
