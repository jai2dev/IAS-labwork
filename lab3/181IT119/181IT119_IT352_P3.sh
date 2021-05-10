#!/bin/bash

python3 sniff_packet.py &
b="$!"
python3 create_packet.py
python3 firewall_filter.py 
