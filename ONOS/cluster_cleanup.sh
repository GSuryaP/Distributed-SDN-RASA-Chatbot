#!/bin/bash
echo "Stopping and removing ONOS + Atomix containers..."
sudo docker rm -f atomix1 atomix2 atomix3 atomix4 atomix5 onos1 onos2 onos3 onos4 onos5
echo "Removing Docker network..."
sudo docker network rm onos-net
echo "Cleanup done."

