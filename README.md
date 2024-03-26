# brigid-mbedtls

## MBed TLSのビルド

`git clone --recursive`でサブモジュールを取り寄せると、生成コードのタイムスタンプが古びてしまう場合がある。

```shell
touch mbedtls/library/psa_crypto_driver_wrappers.h
touch mbedtls/library/psa_crypto_driver_wrappers_no_static.c
```

```shell
make CFLAGS="-O2 -fPIC" -j 8
make check
```

ライブラリだけビルドする。

```shell
make CFLAGS="-O2 -fPIC" -j 8 lib
```
