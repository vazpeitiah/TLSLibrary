#!/bin/bash

date
for ((n=0;n<1000;n++))
do
    #date
    echo $n
    ./client_npq newhope 0
    sleep 1
done

date
for ((n=0;n<1000;n++))
do
    #date
    echo $n
    ./client_npq newhope 1
    sleep 1
done

date
for ((n=0;n<1000;n++))
do
    #date
    echo $n
    ./client_npq newhope 2
    sleep 1
done
