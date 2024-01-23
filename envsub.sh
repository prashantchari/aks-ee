#!/bin/bash

set -o allexport
source .env
set +o allexport


for file in *.parameters.json; do
    echo "Replacing env variables in $file"
    envsubst <"$file" >"$file.tmp"
    # move the temporary file to the original file
    mv "$file.tmp" "$file"
done
