#!/bin/bash

date
for ((n=0;n<100;n++))
do
    echo $n
    ./client newhope 2
    sleep 2.5
done
date
