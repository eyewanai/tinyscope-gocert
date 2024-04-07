#!/bin/bash

go build -v -o gocert main.go

if [ $? -eq 0 ]; then
    echo "Build successful. You can find the executable binary at ./gocert"
else
    echo "Build failed."
fi
