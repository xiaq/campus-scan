#!/bin/sh
bindir="$(dirname "$0")"
destdir="$(date +%Y%m%d)"
if [ -f "$destdir" ]; then
    echo "$destdir already exists"
    exit 1
fi
mkdir "$destdir"
cd "$destdir"
ln -s "$bindir"/web/* .

for sub in uphosts openports; do
    "$bindir"/main.py $sub scan > $sub.json
    "$bindir"/main.py $sub plot < $sub.json
done

