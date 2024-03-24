#! /bin/sh -e
set -o pipefail

for i in test/test*.lua
do
  case X$# in
    X0) lua "$i";;
    *) "$@" "$i";;
  esac
done
