***
TVP
***

Building
========

First generate a private key for the enclave:

   openssl genrsa -3 -out enclave-key.pem 3072

Then build with:

   ENCLAVE_SIGNING_KEY=enclave-key.pem make

Running
=======

Run with:

   ./ve_app -t l -i $SPID init

Where `SPID` is Service Provider ID received during IAS registration. For testing purposes you can provide any 32 nibble long hex string.
