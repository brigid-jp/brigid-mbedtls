# brigid-mbedtls

## MBed TLSのビルド

テストあり。

```shell
make CFLAGS="-O2 -fPIC" -j 8
make check
```

テストなし。

```shell
make CFLAGS="-O2 -fPIC" -j 8 no_test
```
