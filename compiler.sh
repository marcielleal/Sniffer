#!/bin/bash

file_name=$1
echo $file_name
gcc -o ${file_name:0:-2} $file_name
