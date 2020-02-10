#!/bin/bash

mkdir build
pushd build
cmake ..
make -j$(nproc)
make deb
popd
