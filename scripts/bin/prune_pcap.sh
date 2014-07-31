#!/bin/bash

tshark -r $1 -w $2 -R "not tcp.port==$3"
