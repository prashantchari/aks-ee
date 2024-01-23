#!/bin/bash

files=(azuredeploy.parameters.json)

for file in files; do
    echo "Replacing env variables in "
    envsubst <"" >".tmp"
    # move the temporary file to the original file
    mv ".tmp" ""
done
