# RFC3161 Timestamp Authority Client

It's a pure-php RFC3161 Client (query, reply, no verify).
Targeting minimal dependencies: only curl, hash extensions needed.
It does not shell out to `openssl`.
The ASN.1/DER Encoding is "hand-crafted".

This **only** supports SHA512 hashes in the Query.


## Example

This client is supplied the end-point on creation, it creates the hash and query and then requests the reply.
Both of those string-data (tsq, tsr) should be saved along w/the content that would be verifed.

```
$url = 'https://freetsa.org/tsr'; // Pick One
$tac = new \Edoceo\Radix\RFC3161($url);
$tsq = $tac->query($file);
$tsr = $tac->reply();
```

## Examination

The files can be manually examined using the `openssl` too.

```
# View Query:
openssl ts -query -in tsa-query.der -text
# View Reply:
openssl ts -reply -in tsa-reply.der -text
```


## Verification

This library does not support verification, it's better left to an external/independent tool.
Generally, the person doing the verification is different than the person doing the assertion.

```
openssl ts -verify \
	-queryfile tsa-query.der -in tsa-reply.der \
	-CAfile tsa-root.pem -untrusted tsa-cert.pem
```


## Timestamp Authority Servers

There are loads of them, [this gist](https://gist.github.com/Manouchehri/fd754e402d98430243455713efada710) is pretty complete.

### Apple

- url: `http://timestamp.apple.com/ts01`
- docs: ?

You'll need to fetch the certificates from [Apple Certificate Authority](https://www.apple.com/certificateauthority/).
Once downloaded, they should be converted

```
wget https://www.apple.com/appleca/AppleIncRootCertificate.cer
openssl x509 -inform der -in AppleIncRootCertificate.cer -out AppleIncRootCertificate.pem
wget https://www.apple.com/certificateauthority/AppleTimestampCA.cer
openssl x509 -in AppleTimestampCA.cer -out AppleTimestampCA.pem
```

### DigiCert

- url: http://timestamp.digicert.com/
- docs: https://knowledge.digicert.com/solution/SO912.html


### DigiStamp

This system requires an account with DigiStamp.

- url: https://tsa.digistamp.com
- docs: https://www.digistamp.com/support/repository-of-timestamp-public-key-certificates


### FreeTSA - https://freetsa.org

Delivers what it says on the tin; not as widely trusted as others (yet)

- url: https://freetsa.org/tsr
