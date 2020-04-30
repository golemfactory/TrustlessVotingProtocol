***
TVP
***

Building
========

First, generate a private key for signing the enclave::

   openssl genrsa -3 -out enclave-key.pem 3072

Then build with::

   ENCLAVE_SIGNING_KEY=enclave-key.pem make

To make running everything easy install all binaries to a single directory::

   make install PREFIX=`pwd`/test_tools && cd test_tools

Example usage
=============

You will need to register for Intel Attestation Service (IAS) API here (dev access):
https://api.portal.trustedservices.intel.com/EPID-attestation

SPID, quote type (linkable/unlinkable) and an API key are needed later.

First, the Enclave Host (EH) initializes the enclave::

   $ ./eh_app init
   Loading enclave from file 'voting_enclave.signed.so'
   Enclave loaded successfully, id = 0x2
   [VE] Performing global enclave initialization...
   [VE] Enclave initializing...
   [VE] Generating enclave signing key...
   [VE] Sealing enclave state...
   Saving sealed enclave state to 've.state'
   [VE] Enclave public key: 0455950238f73ed6088349506110d57571fd490f011f86e245786fcaa77d9418f43a36cd49c9d047e0122e232f98ba50a2e18f18cc8a5ea79b040ca749976e4136
   [VE] Enclave public key hash: c598e7abaed4bfa52b0c724cf5270ddc2d9980dbeaa14825471093511bde3cf0
   [VE] Enclave initialization OK
   Saving public enclave key to 've_pubkey'
   Enclave unloaded

Then, the EH generates an enclave quote and verifies it with IAS. Enclave's public key hash is
embedded in the ``report_data`` field of the quote which will be important later. ``MR_ENCLAVE``
is the SGX enclave binary hash, everyone building the enclave from the same source should get
the same value. ``MR_SIGNER`` is a hash of the key that was used to sign the enclave. They can
both be verified by voters from the IAS report which is shown later.
::

   $ ./eh_app quote -i $IAS_SPID -t $IAS_QUOTE_TYPE -k $IAS_API_KEY
   Loading enclave from file 'voting_enclave.signed.so'
   ...
   [VE] Enclave initialization OK
   MR_ENCLAVE: 140b863c334077085c46a3eb92db804acad866a2263fcd42fb3fbea2086fcdae
   MR_SIGNER:  577b180dbcdae37bd9f26444189e3ba78ad85bd03515bf26f5c4455c5284b214
   Enclave quote saved to 've.quote'
   IAS nonce: rq3oPM5aLgNA4J0djOPjmvRltCl5aoSw
   IAS report saved to: ve.quote.report
   IAS report signature saved to: ve.quote.report.sig
   Enclave unloaded

Next, the EH generates their keys::

   $ ./eh_app gen-key
   Generating EH key pair...
   EH public key: 042dc764f526e013a563dfdf34d70e2c8e9b18bdd6f507cb419838abdc81d08a1b72c11265a9761807f6e0eb908b5f49da796c6579a9d8752c50f116d1733b3188
   Writing EH private key to 'eh_privkey'
   Writing EH public key to 'eh_pubkey'

and voters generate their keys (key file name is the last parameter)::

   $ python voter.py generate v1
   Public key: 0419189619538aeb34454616deca803d900d997de6edd8033de608ebbe5ab6d4af4642c0bff5dc9a145392aafceb48f4d132470509ad6233761e9645641c5b2b78

   $ python voter.py generate v2
   Public key: 04ed428c65862e1c804531bc4e718d4896f35bf500301f6c063a5e4602fde986db67dbf7696d27b5053d7f694191ea3f946543d14b8fda1a4c59731924d5c52fec

The EH runs the hosting application in an interactive mode::

   $ ./eh_app run

The application loads the enclave and listens for commands on stdio.

Now EH can create a voting::

   Enter a command:
   (s)ubmit a voting
   (b)egin the voting
   (e)nd the voting
   submit a (v)ote
   s
   Enter start time:
   1970-01-01 13:37
   Enter end time:
   1970-02-20 13:37
   Enter number of options:
   5
   Enter number of voters:
   2
   Enter public key (hex) of voter number 1:
   0419189619538aeb34454616deca803d900d997de6edd8033de608ebbe5ab6d4af4642c0bff5dc9a145392aafceb48f4d132470509ad6233761e9645641c5b2b78
   Enter weight of voter number 1:
   3
   Enter public key (hex) of voter number 2:
   04ed428c65862e1c804531bc4e718d4896f35bf500301f6c063a5e4602fde986db67dbf7696d27b5053d7f694191ea3f946543d14b8fda1a4c59731924d5c52fec
   Enter weight of voter number 2:
   1
   Enter description:
   My voting
   [VE] VID: ee86a2915d32efe09bcb7389e9d075d07f6fa15afdbfae5ccbd406f05decc27e
   Voting registration successful
   VDVE nonce: 6de24b8b00fe8892e956fd945f8e851dd8108131a0748f4fb5a7e33a45430b6a
   VDVE signature: 9b4f19a88fced96ada0910deb7a4caa284f394e48da2a3d2055e094734a778d8d155a8e957051bf9b4ffa019677a29534ea3f949afed4a664749c8f0bd87a847
   Enter path to enclave IAS report (empty for default):
   
   VDEH saved to 'vdeh.tvp'

and start it::

   Enter a command:
   (s)ubmit a voting
   (b)egin the voting
   (e)nd the voting
   submit a (v)ote
   b
   Enter VID:
   ee86a2915d32efe09bcb7389e9d075d07f6fa15afdbfae5ccbd406f05decc27e
   [VE] Voting started, VID: ee86a2915d32efe09bcb7389e9d075d07f6fa15afdbfae5ccbd406f05decc27e

Now each voter can validate the voting description::

   $ python verify_voting_sig.py

   Input VDEH path (empty for default):
   VE signature OK
   Input EH pubkey: 042dc764f526e013a563dfdf34d70e2c8e9b18bdd6f507cb419838abdc81d08a1b72c11265a9761807f6e0eb908b5f49da796c6579a9d8752c50f116d1733b3188
   EH signature OK
   VID: ee86a2915d32efe09bcb7389e9d075d07f6fa15afdbfae5ccbd406f05decc27e

and generate their votes::

   $ python voter.py v1

   Input VE public key: 0455950238f73ed6088349506110d57571fd490f011f86e245786fcaa77d9418f43a36cd49c9d047e0122e232f98ba50a2e18f18cc8a5ea79b040ca749976e4136
   Input vid: ee86a2915d32efe09bcb7389e9d075d07f6fa15afdbfae5ccbd406f05decc27e
   Input option: 2
   Encrypted vote: 0482541867571aedb6307c00c5271d7f83826059cb61ae1517a3ac129e1d9b41f9d2e41b720c67ee840f7856cd8b9ce715efb10d85dbec6f38885d2bde70f725dddef8cd0083560a0d3c5ddba5d57da7778dd22b040c223b6c82247b3dd605051f8e2da2de964579adf6125a412c95786e29ae6e5d429cf5d5840ce1e6d4d9074aa455050ce4e9ab841512982bb122512bc7c7a3bcb00bdc75ee27c6ad3108858ca09b2cc06608ad057e38a49984f76ea22d881e01b9074c84e097227260283687fa0dbdf933c4f1ec49caa6f3f04462b4019ad68ea964fe8fa19cfa94b1ba9dca5659969844a98eff63c6e0607d190d46901c579431b56a541d979589cab6f157b7fc4b4be16c6f610dcbd63fe4ad169b

After providing the necessary data it will generate an encrypted vote, which can be pasted into
the EH app::

   Enter a command:
   (s)ubmit a voting
   (b)egin the voting
   (e)nd the voting
   submit a (v)ote
   v
   Enter encrypted vote:
   0482541867571aedb6307c00c5271d7f83826059cb61ae1517a3ac129e1d9b41f9d2e41b720c67ee840f7856cd8b9ce715efb10d85dbec6f38885d2bde70f725dddef8cd0083560a0d3c5ddba5d57da7778dd22b040c223b6c82247b3dd605051f8e2da2de964579adf6125a412c95786e29ae6e5d429cf5d5840ce1e6d4d9074aa455050ce4e9ab841512982bb122512bc7c7a3bcb00bdc75ee27c6ad3108858ca09b2cc06608ad057e38a49984f76ea22d881e01b9074c84e097227260283687fa0dbdf933c4f1ec49caa6f3f04462b4019ad68ea964fe8fa19cfa94b1ba9dca5659969844a98eff63c6e0607d190d46901c579431b56a541d979589cab6f157b7fc4b4be16c6f610dcbd63fe4ad169b
   Encrypted VVR: 12b5da2b4e7bc916bf873a2b18a94e940121255227c550378bf4e8edb74dd2b3bbb2e066d2a4bc04b5f21481d79ab5c5fa745119c956744fd1bd48610a7b9137ed5f4e2e5bc6390f9f81b7830fc5c632de7579d5325cd9fa4f7975c2156654563ba854981bd5021fd86ace734a11a82a0ddad9c0f7774e120c9f5b976f542f683a60c7b83c09a136ef20bee8a08bafd56e5533610c297d468bdee1835f40a12ab70bad208c28fffe76103054375da55ebdd328c7fe6022a117fb29e5c9806b840afedf0c2fc0e99f26ffe7be8ecc7fd1cffbaf61025c97daf3062eb9f63a146c

The EH app will return an encrypted VVR which can be pasted into the voter app for verification::

   Input VVR: 12b5da2b4e7bc916bf873a2b18a94e940121255227c550378bf4e8edb74dd2b3bbb2e066d2a4bc04b5f21481d79ab5c5fa745119c956744fd1bd48610a7b9137ed5f4e2e5bc6390f9f81b7830fc5c632de7579d5325cd9fa4f7975c2156654563ba854981bd5021fd86ace734a11a82a0ddad9c0f7774e120c9f5b976f542f683a60c7b83c09a136ef20bee8a08bafd56e5533610c297d468bdee1835f40a12ab70bad208c28fffe76103054375da55ebdd328c7fe6022a117fb29e5c9806b840afedf0c2fc0e99f26ffe7be8ecc7fd1cffbaf61025c97daf3062eb9f63a146c
   hash(RV): e347fa23b107c073260528e69ccc3f08a70ceb60d829348cc26c5d190eac3a91
   VVR signature OK
   VVR voter public key OK (is ours)
   VVR VID OK
   VVR voter option OK
   VVR verified correctly

After submiting all of the votes, EH can end the voting::

   Enter a command:
   (s)ubmit a voting
   (b)egin the voting
   (e)nd the voting
   submit a (v)ote
   e
   Enter VID:
   ee86a2915d32efe09bcb7389e9d075d07f6fa15afdbfae5ccbd406f05decc27e
   [VE] Voting stopped, VID: ee86a2915d32efe09bcb7389e9d075d07f6fa15afdbfae5ccbd406f05decc27e
   VREH:
   ee86a2915d32efe09bcb7389e9d075d07f6fa15afdbfae5ccbd406f05decc27e0500000000000000030000000100000000000000000000000200000000000000e347fa23b107c073260528e69ccc3f08a70ceb60d829348cc26c5d190eac3a9170463b662a21d707041c8b74f100be5ce9f459a40a7991e94ed2841ceedd1926b7249c3222cd05485cdbc7eed3061f02340cfbafb056db8a152b73af598a09dd39129b598bda061d3c3a202ab709768eeee66d1fa0185d59cdf3801fa88810a70abeae1de4367b34fc9d376c1ceea339c59ec4e9239dfdd4d1da147024fed3a951707bd032cda5e1433c9d485e45b441160ccb4d064ed9a7f333dc101e6f4a19

Each voter can verify the results and that their vote was counted::

   $ python verify_voting_results.py

   Input VREH: ee86a2915d32efe09bcb7389e9d075d07f6fa15afdbfae5ccbd406f05decc27e0500000000000000030000000100000000000000000000000200000000000000e347fa23b107c073260528e69ccc3f08a70ceb60d829348cc26c5d190eac3a9170463b662a21d707041c8b74f100be5ce9f459a40a7991e94ed2841ceedd1926b7249c3222cd05485cdbc7eed3061f02340cfbafb056db8a152b73af598a09dd39129b598bda061d3c3a202ab709768eeee66d1fa0185d59cdf3801fa88810a70abeae1de4367b34fc9d376c1ceea339c59ec4e9239dfdd4d1da147024fed3a951707bd032cda5e1433c9d485e45b441160ccb4d064ed9a7f333dc101e6f4a19
   Input EH public key: 042dc764f526e013a563dfdf34d70e2c8e9b18bdd6f507cb419838abdc81d08a1b72c11265a9761807f6e0eb908b5f49da796c6579a9d8752c50f116d1733b3188
   VREH signature OK
   Inpute VE public key: 0455950238f73ed6088349506110d57571fd490f011f86e245786fcaa77d9418f43a36cd49c9d047e0122e232f98ba50a2e18f18cc8a5ea79b040ca749976e4136
   VRVE signature OK
   Input VID: ee86a2915d32efe09bcb7389e9d075d07f6fa15afdbfae5ccbd406f05decc27e
   VID in VREH matches
   Input your RV hash: e347fa23b107c073260528e69ccc3f08a70ceb60d829348cc26c5d190eac3a91
   Your vote was counted
   Voting results:
    1: 0
    2: 3
    3: 1
    4: 0
    5: 0

Voters can also verify that the enclave is a proper SGX enclave and not a simulation by using the
``verify_ias_report`` utility::

   $ ./verify_ias_report -v -r ve.quote.report -s ve.quote.report.sig -o -n rq3oPM5aLgNA4J0djOPjmvRltCl5aoSw -E 140b863c334077085c46a3eb92db804acad866a2263fcd42fb3fbea2086fcdae
   Verbose output enabled
   Endianness set to LSB
   IAS key: RSA, 2048 bits
   Decoded IAS signature size: 256 bytes
   IAS report: signature verified correctly
   IAS report: allowing quote status GROUP_OUT_OF_DATE
   IAS report: nonce OK
   IAS report: quote decoded, size 432 bytes
   version           : 0200
   sign_type         : 0100
   epid_group_id     : 390b0000
   qe_svn            : 0b00
   pce_svn           : 0a00
   xeid              : 00000000
   basename          : 655afa33faa5b9cc5e9e241fa229b99400000000000000000000000000000000
   report_body       :
    cpu_svn          : 080effff010200000000000000000000
    misc_select      : 00000000
    reserved1        : 000000000000000000000000
    isv_ext_prod_id  : 00000000000000000000000000000000
    attributes.flags : 0700000000000000
    attributes.xfrm  : 0700000000000000
    mr_enclave       : 140b863c334077085c46a3eb92db804acad866a2263fcd42fb3fbea2086fcdae
    reserved2        : 0000000000000000000000000000000000000000000000000000000000000000
    mr_signer        : 577b180dbcdae37bd9f26444189e3ba78ad85bd03515bf26f5c4455c5284b214
    reserved3        : 0000000000000000000000000000000000000000000000000000000000000000
    config_id        : 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
    isv_prod_id      : 0200
    isv_svn          : 0000
    config_svn       : 0000
    reserved4        : 000000000000000000000000000000000000000000000000000000000000000000000000000000000000
    isv_family_id    : 00000000000000000000000000000000
    report_data      : c598e7abaed4bfa52b0c724cf5270ddc2d9980dbeaa14825471093511bde3cf00000000000000000000000000000000000000000000000000000000000000000
   Quote: mr_enclave OK

The ``-o`` option allows to accept quotes from not fully up-to-date platforms (missing BIOS or
firmware updates). The ``-E`` option verifies the enclave SGX hash (``MR_ENCLAVE``) which ensures
that the enclave source/binary is unmodified. The ``-n`` option enables checks for nonce provided
during a IAS request (done by the EH), this may not be needed.

At the end of the quote structure we can see hex values in the ``report_data`` field -- this should
be the hash of enclave's public key. If they match, we can be sure that this quote was generated by
a genuine SGX enclave that possesses the private key matching the known public key.
