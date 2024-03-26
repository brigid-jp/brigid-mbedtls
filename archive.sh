#! /bin/sh -e

here=`dirname "$0"`
here=`(cd "$here" && pwd)`

cd "$here"
version=`cat brigid-mbedtls-version`
version=`expr "X$version" : 'X"\([^"]*\)"'`

git ls-files --recurse-submodules
# git archive --prefix "$prefix/" HEAD
# (cd mbedtls && git archive --prefix "$prefix/mbedtls/" HEAD)
