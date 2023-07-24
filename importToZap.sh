#!/bin/bash


echo "Please make sure zap is running on port 8080. Continue? (Y/n)"
read ZAPPROCESS

if [[ "$ZAPPROCESS" =~ ^([yY][eE][sS]|[yY])$ ]]
then
    continue
else
    echo "Please start ZAP using package."
    exit 0
fi

echo "Please enter ZAP API Key. Can be obtained from ZAP -> Tools -> Options -> API -> copy API Key."
read ZAPAPI

EXCLUDEHELPER="helper"
SCRIPTSDIR="`pwd -P`/scripts"

for SCRIPT in $SCRIPTSDIR/*/*.js
do
    FILENAME="${SCRIPT##*/}"
    TOPLEVEL="${FILENAME%.*}"
    SCRIPTTYPE="${TOPLEVEL##*.}"
    SCRIPTNAME="${TOPLEVEL%%.*}"
    if [[ "$SCRIPTTYPE" != "$EXCLUDEHELPER" ]]
    then
        curl "http://localhost:8080/JSON/script/action/load/?apikey=$ZAPAPI&scriptName=$SCRIPTNAME.js&scriptType=$SCRIPTTYPE&scriptEngine=Graal.js&fileName=$SCRIPT&charset=UTF-8"
    else
        continue
    fi
done
