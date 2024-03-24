# brigid-mbedtls

## MBed TLSのビルド

テストあり。

```shell
make -j 8
make check
```

テストなし。

```shell
make -j 8 no_test
```

## 初期方針

- [ ] 乱数
- [ ] base64 / base64url
- [ ] JWTの生成に必要な機能
- [ ] JWTの検証に必要な機能
