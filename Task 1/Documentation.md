# 1 Root CA and Root Certificate

A root CA is a Root Certificate Authority. It is the highest authority in the PKI (Public Key Infrastructure) and works by the principle of a friend of yours is also a friend of mine.

A root CA signs and gives out certificates to other parties. If you trust the root CA (e.g. Google), then you can also trust the party that got its certificate from the Root CA.

Our root CA Key is protected by a password (BierTrinken) in this case, which is important to keep the Root CA protected. Because the root CA key is the single most important thing in a PKI, because with that we can hand out other certificates.

In this case, the password is not encrypted itself or protected in any kind. That is in order to be reproduceable. However, in a production environment, this password and the CA key must be highly protected.

# 2 PKCS#10 and CSR (Certificate Sign Request)

PKCS#10 (Public Key Cryptography Standards number 10) is a standard for used to create create a Certificate Sign Request.

And the certificate signing request is in essence a small blob with three things. A public key, the requested subject name (e.g. "BierTrinken Server") and optionally the requested certificate extensions

Important to notice in a CSR (Certificate Sign Request) is that it has no validity period itself, the validity period is on the certificate that comes back and is placed on there by the CA (Certificate Authority)

The private key for our server, the one we sign our server certificate with, is not password protected, unlike the private key of the CA. This is because a server often has to autonomously restart, and cannot wait for someone to come in and type in the password. But often is correct filesystem permissions also sufficient for this key.

You can see the CSR in server.cnf. In there some thing are defined about the certificate, we also define the followig extentions. The meaning of which have I generated with AI

> AI Generated meanings of the Extensions in the CSR

basicConstraints = critical,CA:FALSE — this is a leaf certificate, it must never be able to sign other certificates. Omitting this is how you get a "web server cert" that can mint arbitrary certs if the issuing CA is sloppy.

keyUsage = digitalSignature,keyEncipherment — digitalSignature for ECDHE handshakes (the signature over the key exchange), keyEncipherment for legacy RSA key transport. Constrains the key to exactly what a TLS server needs.

extendedKeyUsage = serverAuth — this key authenticates a server, not a client, not a code signer. Narrows it further.

subjectAltName — the one that actually matters. Since 2017 every mainstream client (Chrome, Firefox, curl, Go, modern OpenSSL) ignores the CN entirely for hostname verification. RFC 2818's CN fallback was deprecated by RFC 6125 and removed from implementations. A certificate with a perfect CN and no SAN is simply invalid for any hostname — browsers throw ERR_CERT_COMMON_NAME_INVALID.

Missing SAN is the single most common defect in LLM-generated PKI scripts, because the models were trained on a decade of pre-2017 tutorials. Put it at the top of your findings list, and be ready to demonstrate it: generate one cert without SAN and show openssl verify passing while curl rejects it. That contrast is exactly the kind of evidence requirement (7) is asking for.

## X.509 certificate extensions
Certificate extensions are optional fields an an X.509 certificate and let a CA (Certificate Authority) add extra information to the certificate. For example it can add usage restrictions or alternative subject names, etc.

# Handing our a certificate
So we can request the certificate with our CSR and then the CA hands the signed certificate back.

However, a big problem with these X509 certificates is that they are stateless. So there is no possibility to revoke one. The only way we can revoke one is by keeping a database or list of revoked CA's. This is in practise also what real root CA's do.

Some things to tease you for the Privacy and Cryptograhpy class are CRL (Certificate Revocation List) and OSCP Stapling (Online Certificate Status Protocol). Both ways of revoking a handed out certificate.