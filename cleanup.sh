#! /bin/bash

# Killing containers which has label of "hkn"

docker kill $(docker ps -q --filter "label=hkn")
#time docker ps --no-trunc --filter "label=hkn" --format '{{.ID}}' | xargs -n 1 docker inspect --format '{{.State.Pid}}' $1 | xargs -n 1 sudo kill -9
# Removing killed containers which have label of "hkn"

docker rm $(docker ps -q -a --filter "label=hkn" --filter status=exited)
# Prune Network bridges which are not used by any container

docker network prune -f


