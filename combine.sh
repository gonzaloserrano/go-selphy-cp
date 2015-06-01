#! /bin/bash

# put the two squared images passed as parameter in a single one
# separated by a space so you can for e.g print two instagram
# pictures in one selphy print.
# Needs imagemagic: $ brew install imagemagic

f1=$(basename "$1")
ext1="${f1##*.}"
f1="${f1%.*}"

f2=$(basename "$2")
ext2="${f2##*.}"
f2="${f2%.*}"

echo "$1"  + middle.png  + "$2" = comb-"$f1"-"$f2".png
convert +append -background none "$1"[640x640] middle.png "$2"[640x640] comb-"$f1"-"$f2".png
