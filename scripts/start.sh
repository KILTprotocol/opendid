#! /bin/bash

runtime="$RUNTIME"

if [ "$runtime" == "peregrine" ]; then
        /app/opendid_peregrine --config /app/config.yaml
        exit 0
fi

if [ "$runtime" == "spiritnet" ]; then
        /app/opendid_spiritnet --config /app/config.yaml
        exit 0
fi

echo "no runtime specified"
exit 1
