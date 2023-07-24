#!/bin/bash


OS=$(uname -s)
if [ "$OS" = "Darwin" ]; 
then
    ZAPDIR="$HOME/Library/Application Support/ZAP"
else
    echo "Please enter ZAP's home directory. Usually, it is -> C:/Program Files/OWASP ZAP/"
    read ZAPDIR
fi
echo "ZAP Package folder - $ZAPDIR"

SCRIPTSDIR="`pwd -P`/scripts"

if [ -d "$ZAPDIR" ]
then
    cd "$ZAPDIR"
    if [ -d "$ZAPDIR/astra-scripts" ]
    then
        echo "Directory for helper scripts exists. Overwrite files? (Y/n) "
        read OVERWRITEHELPER
        if [[ "$OVERWRITEHELPER" =~ ^([yY][eE][sS]|[yY])$ ]]
        then
            cp -r "$SCRIPTSDIR/helper" "$ZAPDIR/astra-scripts"
        else
            echo "Helper function scripts remain untouched."
        fi
    else
        mkdir "astra-scripts"
        cp -r "$SCRIPTSDIR/helper" "$ZAPDIR/astra-scripts"
        echo "Copied helper function files from $SCRIPTSDIR/helper to $ZAPDIR/astra-scripts/helper"
    fi
else
    echo "Are you sure the ZAP Package folder path is correct?"
    exit 0
fi

cd "$SCRIPTSDIR"
cd ..
./importToZap.sh
