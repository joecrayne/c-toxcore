#!/bin/sh

CMAKE=cmake
NPROC=`nproc`
CURDIR=$PWD

RUN() {
  "$@"
}

TESTS() {
  "$@"
}