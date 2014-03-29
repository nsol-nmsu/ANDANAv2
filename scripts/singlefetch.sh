uri="$1"
val="$2"
ccnpeek -a -u -l 30 -w 30 $uri/$val
TIMEFORMAT=%R
while [ $? -ne 0 ]; do
    echo "Trying again.."
    ccnpeek -a -u -l 30 -w 30  $uri/$val;
done
