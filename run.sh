#!/bin/sh
bindir=$(dirname "$(readlink -f "$0")")
do_scan=no
do_plot=no

while [ "$#" -gt 0 ]; do
    case "$1" in
    -s)
        do_scan=yes ;;
    -p)
        do_plot=yes ;;
    *)
        dest_dir=$1 ;;
    esac
    shift
done

if [ -z "$dest_dir" ]; then
    dest_dir="$(date +%Y%m%d)"
    if [ -f "$dest_dir" ]; then
        echo "$dest_dir already exists"
        exit 1
    fi
fi

mkdir "$dest_dir"
cd "$dest_dir"

[ "$do_plot" = yes ] && ln "$bindir"/web/* .

for sub in uphosts openports; do
    [ "$do_scan" = yes ] && "$bindir"/main.py $sub scan -f $sub.json
    [ "$do_plot" = yes ] && "$bindir"/main.py $sub plot -f $sub.json
done

