#!/bin/bash

rm -f ./grading/nyufile.tar.xz

tar cvJf nyufile.tar.xz Makefile nyufile.cpp

cp nyufile.tar.xz ./grading/nyufile.tar.xz

cd ./grading/

./autograder.sh