#!/bin/bash
uri="$1"
trials="$2"
echo Fetching file prefix $uri for $trials trials
index=0
while [  $index -lt $trials ]; do
	echo Fetching file index $index
	echo ./ccngetfile $uri/$index.dump
	# ./ccngetfile $uri_$index
#	FETCHTIME=$((( command time -f '%e' ./ccngetfile $uri/$index.dump $index.retr.dump; ) 1>dump; ) 2>&1; )
#	echo $FETCHTIME

	# Loop until the damn data is actually fetched...
        { time (
                ./ccngetfile $uri/$index.dump $index.retr.dump
                while [ $? -ne 0 ]; do
                        ./ccngetfile $uri/$index.dump $index.retr.dump;
                done
        ) } 2>&1


	let index=index+1
done

