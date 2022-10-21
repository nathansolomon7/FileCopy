#!/bin/bash
dir=`pwd`
srcPath=$dir/SRC
targetPath=$dir/TARGET


for FILE in "$srcPath"/*; do

if ! cmp $FILE $dir/TARGET/$(basename $FILE) > /dev/null 2>&1
echo $(basename $FILE)
then
  echo true
else
  echo false
fi
done