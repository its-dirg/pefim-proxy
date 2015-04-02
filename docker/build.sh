#!/bin/sh
docker -f rmi pefim_proxy
docker build -t pefim_proxy .