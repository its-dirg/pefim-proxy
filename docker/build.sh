#!/bin/sh
docker rmi -f pefim_proxy
docker build -t pefim_proxy .