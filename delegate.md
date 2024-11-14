
# Design Notes:

The "key Type" from delegate keys (certs) isn't really authorative, because certs chains may have a combinition
of different keys, and because delegate chains will be used for both RV blobs and TO2 services.
We have added "names" to allow people to create different chains of different types for use in 
either of these.

The "keyType" field however is still used primarily for compatibility, and it referse to the leaf (first)
certificate in the chain - i.e. the one which directly reflects the ("owner") key of the actual server.
(i.e. NOT necessarily the root "owner" key)

The rest of the implmentation starts with a device key (type) that is created during DI, then during
onboarding, the rest of the exchanges are done to an owner key of that same type (i.e. device provides
eASignInfo during TO2.HelloDevice, and Onboarding Server then provides and owner key of the same type.

There is no guarentee that an X5Chain will have all the same keys of a certian-type only, especially when
onboarding devices of different types. 


# Command Cheat-Sheet

```
go run ./examples/cmd server -debug -db test.db -print-owner-public SECP384R1 > /tmp/mykey.key
openssl x509   -text -noout -in /tmp/mychain.cert

go run ./examples/cmd server -debug -db test.db -print-owner-chain SECP384R1 > /tmp/mychain.cert
openssl pkey  -pubin  -text -noout -in /tmp/mykey.key

go run ./examples/cmd server -debug -db test.db -print-owner-private SECP384R1 > /tmp/mypriv.key
openssl pkey  -text -noout -in /tmp/mypriv.key

go run ./examples/cmd server -debug -db test.db -delegate -owner-certs
openssl x509   -text
```


# Run TO0 on a specifc GUID:
sqlite3 test.db 'select hex(guid) from owner_vouchers;'
go run ./examples/cmd server -debug --reuse-cred -db test.db -to0 http://127.0.0.1:8080 -to0-guid 32F7F3CE7F029EE2C10074F4C1DCF565




Figure 7 is wrong? TO0.OwnerSign is not signed by Ownerkey (to1d is, though)


# Manual Step Flow test:

```
rm test.db
go run ./examples/cmd server -debug -owner-certs  -db test.db -delegate
go run ./examples/cmd/ client -debug -di http://127.0.0.1:8080
sqlite3 test.db 'select hex(guid) from owner_vouchers;'
go run ./examples/cmd server -debug --reuse-cred -db test.db -to0 http://127.0.0.1:8080 -to0-guid  <from_previous_line> -delegate
go run ./examples/cmd client  -rv-only -debug
go run ./examples/cmd client  -debug
```

NOTE: if you don't manually register blob by manually running to0 above with `-delegate` flag - you will get no delegate in RV blob

Convert hex bytestream to SSL cert:
`/home/bkg/bytestocert/bytestocert | openssl x509 -text`
