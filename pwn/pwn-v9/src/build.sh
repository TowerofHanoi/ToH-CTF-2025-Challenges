#!/bin/bash

git clone https://github.com/vim/vim.git
cd vim
git checkout 0e40501a9d1ff9bd06f8a829a8a255a0964edb3c  # Nothing special, just the latest commit while I was creating the Dockerfile

git apply ../jail.patch
git apply ../security.patch
git apply ../bug.patch

./configure
make -j16
cd ..
cp ./vim/src/vim ridiculous_vim
rm -rf vim
