#!/bin/bash

date
for ((n=0;n<999999;n++))
do
    echo $n
    ./server_npq
    sleep 2.5
done
date
