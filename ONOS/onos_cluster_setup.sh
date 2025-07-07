#!/bin/bash

# CONFIGURATION
ATOMIX_VERSION="3.1.5"
ONOS_IMAGE="onosproject/onos:2.2.2"
NETWORK_NAME="onos-net"
SUBNET="10.0.0.0/24"

# IP Assignments
ATOMIX_IPS=("10.0.0.11" "10.0.0.12" "10.0.0.13" "10.0.0.14" "10.0.0.15")
ONOS_IPS=("10.0.0.21" "10.0.0.22" "10.0.0.23" "10.0.0.24" "10.0.0.25")
HOSTS=("atomix1" "atomix2" "atomix3" "atomix4" "atomix5" "onos1" "onos2" "onos3""onos4" "onos5")

# SETUP START
echo "👉 Cleaning up old containers and network..."
sudo docker rm -f "${HOSTS[@]}" &>/dev/null
sudo docker network rm $NETWORK_NAME &>/dev/null

echo "🔧 Creating Docker network $NETWORK_NAME..."
sudo docker network create --subnet=$SUBNET $NETWORK_NAME

# Run Atomix containers
echo "🚀 Starting Atomix containers..."
for i in "${!ATOMIX_IPS[@]}"; do
    sudo docker run -d --name atomix$((i+1)) --net=$NETWORK_NAME --ip=${ATOMIX_IPS[$i]} atomix/atomix:$ATOMIX_VERSION
done

# CD to ONOS
cd onos

# Generate Atomix configs (skip if exists)
echo "🛠️ Preparing Atomix configs..."
for i in "${!ATOMIX_IPS[@]}"; do
    CONF_FILE=~/atomix$((i+1)).conf
    if [ -f "$CONF_FILE" ]; then
        echo "✅ Reusing existing $CONF_FILE"
    else
        echo "📄 Generating $CONF_FILE..."
        ./tools/test/bin/atomix-gen-config "${ATOMIX_IPS[$i]}" "$CONF_FILE" "${ATOMIX_IPS[@]}"
    fi
done

# Copy config into Atomix containers
echo "📦 Copying Atomix configs to containers..."
for i in "${!ATOMIX_IPS[@]}"; do
    sudo docker cp ~/atomix$((i+1)).conf atomix$((i+1)):/opt/atomix/conf/atomix.conf
done

# Restart Atomix
echo "🔁 Restarting Atomix containers..."
sudo docker restart atomix1 atomix2 atomix3 atomix4 atomix5

# Start ONOS containers
echo "🚀 Starting ONOS containers..."
GUI_PORTS=("8181:8181" "8182:8181" "8183:8181" "8184:8181" "8185:8181")
CLI_PORTS=("8101:8101" "8102:8101" "8103:8101" "8104:8101" "8105:8101")
MN_PORTS=("6653:6653" "6654:6653" "6655:6653" "6656:6653" "6657:6653")
for i in "${!ONOS_IPS[@]}"; do
    sudo docker run -d --name onos$((i+1)) --net=$NETWORK_NAME --ip=${ONOS_IPS[$i]} -p ${MN_PORTS[$i]} -p ${GUI_PORTS[$i]} -p ${CLI_PORTS[$i]} $ONOS_IMAGE
done

# Generate ONOS cluster configs (skip if exists)
echo "🛠️ Preparing ONOS cluster configs..."
for i in "${!ONOS_IPS[@]}"; do
    CONF_FILE=~/cluster$((i+1)).json
    if [ -f "$CONF_FILE" ]; then
        echo "✅ Reusing existing $CONF_FILE"
    else
        echo "📄 Generating $CONF_FILE..."
        ./tools/test/bin/onos-gen-config "${ONOS_IPS[$i]}" "$CONF_FILE" -n "${ATOMIX_IPS[@]}"
    fi
done

# Copy ONOS configs into containers
echo "📦 Copying ONOS configs to containers..."
for i in "${!ONOS_IPS[@]}"; do
    sudo docker exec onos$((i+1)) mkdir -p /root/onos/config
    sudo docker cp ~/cluster$((i+1)).json onos$((i+1)):/root/onos/config/cluster.json
done

# Restart ONOS
echo "🔁 Restarting ONOS containers..."
sudo docker restart onos1 onos2 onos3 onos4 onos5

cd ..
echo "✅ Cluster setup complete!"
echo "🌐 Access ONOS-1 GUI: http://localhost:8181/onos/ui" 
echo "🌐 Access ONOS-2 GUI: http://localhost:8182/onos/ui"
echo "🌐 Access ONOS-3 GUI: http://localhost:8183/onos/ui"
echo "🌐 Access ONOS-4 GUI: http://localhost:8184/onos/ui"
echo "🌐 Access ONOS-5 GUI: http://localhost:8185/onos/ui"
echo "(user: onos, pass: rocks)"

