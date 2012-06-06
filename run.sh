#!/bin/sh

ln_or_cp() {
    ln "$@" || cp "$@"
}

on_exit() {
    STATUS=$?
    rm "$lock_file_f"
    exit "$STATUS"
}

bindir=$(dirname "$(readlink -f "$0")")
do_scan=no
do_plot=no
set_verbose=no

TEMP=$(getopt -o spv -- "$@")
if [ $? != 0 ]; then
    echo 'Terminating...'
    exit 1
fi

eval set -- "$TEMP"

while [ "$#" -gt 0 ]; do
    case "$1" in
    -s)
        do_scan=yes ;;
    -p)
        do_plot=yes ;;
    -v)
        set_verbose=yes ;;
    --)
        shift
        break ;;
    esac
    shift
done

dest_dir="$1"

[ "$set_verbose" = yes ] && set -v

lock_file=campus-scan.lock

if [ -e "$lock_file" ]; then
    echo 'Lock exists, exiting...'
    exit 1
else
    touch "$lock_file"
    lock_file_f="$(readlink -f "$lock_file")"
    trap on_exit INT QUIT TERM
fi

if [ -z "$dest_dir" ]; then
    dest_dir="$(date +%Y%m%d)"
    if [ -e "$dest_dir" ]; then
        echo "$dest_dir already exists"
        exit 1
    fi
fi

mkdir "$dest_dir"
cd "$dest_dir"

[ "$do_plot" = yes ] && ln_or_cp "$bindir"/web/* .

for sub in uphosts openports; do
    [ "$do_scan" = yes ] && "$bindir"/main.py $sub scan -f $sub.json
    [ "$do_plot" = yes ] && "$bindir"/main.py $sub plot -f $sub.json
done

