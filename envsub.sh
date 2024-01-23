#!/bin/bash

# set -o allexport
# source .env
# set +o allexport
# Uses exported variables on the shell
# To export from the .env file to the shell use `export $(cat .env | xargs)`

for file in *.parameters.json; do
    echo "Replacing env variables in $file"
    envsubst <"$file" >"$file.tmp"
    # move the temporary file to the original file
    mv "$file.tmp" "$file"
done
