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

## 初期方針

- [ ] 乱数
- [ ] base64 / base64url
- [ ] JWTの生成に必要な機能
- [ ] JWTの検証に必要な機能
