# foxpass-setup
Scripts for setting up Foxpass integration in common environments

# Run docker images
## Build ubuntu image (Testing purposes only)

`docker build -f docker/Docker_ubuntu1804 -t docker_ubuntu1804 .`

## Run ubuntu image (Testing purposes only)

`docker run --rm -e API_KEY={API_KEY} -e BASE_DN={BASE_DN} -e BIND_USER={BIND_USER} -e BIND_PASSWORD={BIND_PASSWORD} -ti docker_ubuntu1804`

See the available [Dockerfiles](https://github.com/foxpass/foxpass-setup/tree/master/docker).