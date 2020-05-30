#!/usr/bin/env bash

GOOS=linux GOARCH=amd64 CGO_ENABLED=0 GOGC=off go build -ldflags "-s" -a