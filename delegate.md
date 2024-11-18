
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

# Theory

## Chain Keys and Types
Remeber that normally an RV blob or TO2 OwnerSign is signed directly by Owner like `Owner->Blob` (i.e. Owner Signs Blob).
But with Delegate, a delegate cert can sit in the middle like: `Owner->Delegate->Blob` (i.e. Owner signs Delegate cert, key in Delegate Cert signs blob).
But Delegate chains can get more complex like: `Owner->Delegate1->Delegat2->Delegate3->Blob`

Note that this implies:
* The first cert in the chain must always be signed by "Owner" key (i.e. an owner key of a given type)
* The cert will be one in which we must retain the PrivateKey, as our FDO Server will require this to be *that* delegate, and sign things (blobs, Proofs) with that delegate key

Thus in the commands below, the first key type (`ownerKeyType`) must be a valid, existing Owner Key (in the database), and this private key (in the database) will be used to sign the first cert in our chain. Each other cert in the chain just signs the next. (We we will never use these keys for signing anything else, we don't store them - we just thrown them away).

But the last cert in the chain, we will retain the Private Key, as anything signed with this chain is actually signed by this last (delegate) cert.

Also note, that unlike other systems (like TLS) where when a private (Root CA) is created, a well-known Root CA Certificate is 	also created and subsqeuently referenced - in FDO - when we create an initial "Owner" key, we don't necessarily create or retain any such certificate. Therefore, when we create a Delegate chain (with this tool), we will create an "Owner CA"  cert at the root of each chain, signing it with the Private Key of the applicable `ownerKeyType` type.

## Permissions
Delegate certs can be scoped to only be allowed to do specific things, such as:
* `onboard` - Onboard a device - i.e. Hold the key used by a server to onboard during TO2 (sign Proof)
* `redirect` - Sign a redirect blob - i.e. Hold the key used by a server to sign the blob and give to RV server during TO0

(There are others that are not used or implemented here - see specification)

These permissions are specified in the x509 certiticate chains with a special OID. A cert may have one or more permissions/OIDs specified. The rules are:

* A delegate cert must contain a given OID to be granted permission to perform that operation
* A delegate cert must be signed (directly) by owner or...
* A delegate cert must be signed by a cert with a given permission - to be granted that permission
* Any intermediate certs must  contain the specified permission as well to be valid.

i.e. For a delegate cert to be granted permission "X", ALL certs in the chain (from the owner, downward) MUST have permission "X".

(Thus in our utility below, when we create a chain with one or more "Permissions" - these permissions are added to every cert in the chain.
 


# Delegate Create 
`go run ./examples/cmd delegate -db test.db create <chainName> <Permission[,Permission...]> ownerKeyType [keyType...]`


# Delegate Create 
`go run ./examples/cmd delegate -db test.db print <chainName>`

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


Convert hex bytestream to SSL cert:
`/home/bkg/bytestocert/bytestocert | openssl x509 -text`

# Full Delegate test
## Client Side
```
rm test.db
go run ./examples/cmd server -debug -owner-certs  -db test.db -onboardDelegate test2 -rvDelegate test2 -reuse-cred
```

## Server Side
```
go run ./examples/cmd delegate -db test.db create test2 onboard,redirect SECP384R1 SECP384R1 SECP384R1
go run ./examples/cmd/ client -debug -di http://127.0.0.1:8080
GUID=`sqlite3 test.db 'select hex(guid) from owner_vouchers;'`
go run ./examples/cmd server -debug --reuse-cred -db test.db -to0 http://127.0.0.1:8080 -rvDelegate test2 -to0-guid $GUID 
go run ./examples/cmd client  -rv-only -debug
go run ./examples/cmd client  -debug
```
