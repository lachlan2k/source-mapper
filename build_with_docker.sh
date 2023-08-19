#!/bin/bash

docker run --rm -w /src -v $(pwd):/src gradle:6-jdk11 gradle build --no-daemon