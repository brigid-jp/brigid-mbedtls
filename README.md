# brigid-mbedtls

## MBed TLSのビルド

```shell
make CFLAGS="-O2 -fPIC" -j 8
make check
```

ライブラリだけビルドする。

```shell
make CFLAGS="-O2 -fPIC" -j 8 lib
```
