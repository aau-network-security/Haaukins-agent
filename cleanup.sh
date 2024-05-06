#! /bin/bash

docker kill $(docker ps -q --filter "label=hkn")
#time docker ps --no-trunc --filter "label=hkn" --format '{{.ID}}' | xargs -n 1 docker inspect --format '{{.State.Pid}}' $1 | xargs -n 1 sudo kill -9
# Removing killed containers which have label of "hkn"

docker rm $(docker ps -q -a --filter "label=hkn" --filter status=exited)
# Prune Network bridges which are not used by any container

docker network prune -f

#Remove vms
VBoxManage list runningvms | awk '{print $2;}' | xargs -I vmid VBoxManage controlvm vmid poweroff

kaliFound=false
for OUTPUT in `VBoxManage list vms`
do
    echo "testing $OUTPUT"
    if [[ $OUTPUT == *"kali"* ]]; then
        kaliFound=true
        #echo $OUTPUT | awk '{print $2;}' | xargs -I vmid VBoxManage unregistervm --delete vmid
    fi
    if [[ $kaliFound == false ]] && [[ $OUTPUT == "{"* ]]; then
        echo "deleting image $OUTPUT"
        echo $OUTPUT | xargs -I vmid VBoxManage unregistervm --delete vmid
    fi
    if [[ $kaliFound == true ]] && [[ $OUTPUT == "{"* ]]; then
        echo "will not delete image $OUTPUT"
        echo $kaliFound
        kaliFound=false
    fi
done

#Remove wireguard config and interfaces
for INTERFACE in $(sudo wg | grep interface: | awk '{print $2}')
do
        echo $INTERFACE
        sudo wg-quick down $INTERFACE
done

rm -rf /etc/wireguard/*

rm -rf filetransfer/*
