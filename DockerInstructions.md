# How to create the Docker auth secret string:
cat ~/.docker/config.json | base64 -w0

# How to login to the private Docker Registry:
docker login -u "docker-user" docker-registry.wpmt.org
## And the password is related to Ansible 


# How to build an image on local machine:
docker build -t dev/___IMAGE_NAME___:___VERSION___ -f Dockerfile .

# How to push a local image to the private Docker Registry:
## First we need to add a for the private Registry
docker tag dev/___IMAGE_NAME___:___VERSION___ docker-registry.wpmt.org/docker-user/___IMAGE_NAME___:___VERSION___
## Then we push the tag to the private Registry
docker push docker-registry.wpmt.org/docker-user/___IMAGE_NAME___:___VERSION___