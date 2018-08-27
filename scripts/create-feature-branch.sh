#!/bin/bash
MILESTONE=$1
FEATURE=$2
git checkout  $MILESTONE+next-major
git pull
git push origin HEAD:$MILESTONE-$FEATURE
git pull
git checkout $MILESTONE-$FEATURE
echo "started with  $MILESTONE-next-major" > README
git add README
git commit -a -m "initial README"
git push

