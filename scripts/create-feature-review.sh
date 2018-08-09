#!/bin/bash
MILESTONE=$1
FEATURE=$2
git checkout $MILESTONE-$FEATURE
git push origin HEAD:refs/for/$MILESTONE-$FEATURE

