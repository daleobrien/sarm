#!/usr/bin/env bash

docker build --platform linux/arm64 . -t sarm
docker run -p 8443:8443 --rm -it sarm
