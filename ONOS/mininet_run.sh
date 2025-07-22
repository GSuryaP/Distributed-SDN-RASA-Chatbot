#!/bin/bash

echo "🧠 Cleaning any previous Mininet state..."
sudo mn -c

echo "🚀 Launching Mininet with hierarchical topology and multiple controllers..."
sudo mn --custom custom_topos.py --topo hiertopo \
  --switch ovsk,protocols=OpenFlow13 \
  --controller=remote,ip=10.0.0.21,port=6653 \
  --controller=remote,ip=10.0.0.22,port=6653 \
  --controller=remote,ip=10.0.0.23,port=6653 \
  --controller=remote,ip=10.0.0.24,port=6653 \
  --controller=remote,ip=10.0.0.25,port=6653

