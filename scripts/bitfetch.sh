#!/bin/bash

use Time::HiRes qw(usleep nanosleep);

uri="$1"
trials="$2"
sleepBound="$3"
echo Fetching file prefix $uri for $trials trials
index=0
TIMEFORMAT=%R
while [  $index -lt $trials ]; do
    val=$index
    let sleepTime=$(($[ ( $RANDOM % $sleepBound )  + 1 ] * 1000000))
	echo $sleepTime
#    sleep $sleepTime
#    use Time::HiRes qw/ time sleep /;
#    timeParam="'Time::HiRes::usleep "
#    timeParam+=$sleepTime 
#    timeParam+="'"
#    echo $timeParam
#    perl -MTime::HiRes -e $timeParam 
    usleep($sleepTime)
# 'Time::HiRes::usleep ' + $sleepTime 
    echo slept!
    sleep 5
#    echo sleep $sleepTime
    { time ./singlefetch.sh $uri $val > dump ; } 2>> time.out
#    time ./singlefetch.sh $uri $val
    let index=index+1
done
echo "Done!"
