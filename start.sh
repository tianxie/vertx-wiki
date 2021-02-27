#!/bin/bash -x

DOCKER_SOCKET=/var/run/docker.sock
DOCKER_GROUP=docker

if [ -S ${DOCKER_SOCKET} ]; then
    DOCKER_GID=$(stat -c '%g' ${DOCKER_SOCKET})
    getent group docker || groupadd -for -g ${DOCKER_GID} ${DOCKER_GROUP} && usermod -aG ${DOCKER_GROUP} jenkins
fi

/usr/sbin/sshd -D
