#! /bin/sh -e

here=`dirname "$0"`
here=`(cd "$here" && pwd)`

cd "$here"
version=`cat brigid-mbedtls-version`
version=`expr "X$version" : 'X"\([^"]*\)"'`
prefix=brigid-mbedtls-$version

git archive --prefix "$prefix/" HEAD | (cd brigid && tar xf -)
(cd mbedtls && git archive --prefix "$prefix/mbedtls/" HEAD) | (cd brigid && tar xf -)

cd brigid
(cd "$prefix/mbedtls" && rm -r docs programs tests visualc && mkdir tests)
tar cf - "$prefix" | gzip -9 >"$prefix.tar.gz"
