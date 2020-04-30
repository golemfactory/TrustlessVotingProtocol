***
TVP
***

Building
========

First generate a private key for the enclave:

   openssl genrsa -3 -out enclave-key.pem 3072

Then build with:

   ENCLAVE_SIGNING_KEY=enclave-key.pem make

Example usage
=============

First, initialize the enclave:

   ./eh_app init

the Enclave Host (EH) - generates keys:

   ./eh_app gen-key

and a voter:

   python voter.py generate

All of this steps will print respective public keys.

Then run the Enclave Host (EH) application:

   ./eh_app run

This will also spawn the enclave. EH app will listen for commands on stdio.
Now you can create a voting:
::

   Enter a command:
   (s)ubmit a voting
   (b)egin the voting
   (e)nd the voting
   submit a (v)ote
   s
   Enter start date:
   1970-01-01 13:37
   Enter end date:
   1970-02-20 13:37
   Enter number of options:
   5
   Enter number of voters:
   2
   Enter public key (hex) of voter number 0:
   04d5092604d4439f454c283af025d26cbf8bfc8edde8b477f1249e13a4380e059fb4fa52ff023feefd9855e784cad363637321c5a8a516d9d62e391c29ccdb3d80
   Enter weight of voter number 0:
   1
   Enter public key (hex) of voter number 1:
   046c43fcb40cb533044836c530fd897b1f0a23e9bd5869fdfca1d90ba930662349213e978353edea14ee24daf3b2190e52054eebfcc89c4469c340c02e74d57333
   Enter weight of voter number 1:
   1
   Enter description:
   My voting
   [VE] VID: 450215d32401d332a38359e75df7c553ff90d11ab59681011ec0df92b5ac7b0d
   Nonce: 80e66e26b3108a35c24d73c65cbb0b5e1c0c33c87242c5b1ec9125ac9f7e685a
   Sig: 4dd18d68b5f985bb9ac24533d90963f83a7c38295f837a48a92211f3cc46eeec11dbafd14a2386d837c40bbc465db64e719bd9254c0c107d30d6fb63e8b9bf70
   Voting registration successful
   
   Enter path to enclave IAS report (empty for default):
   
   VDEH saved to 'vdeh.tvp'

and start it:
::

   Enter a command:
   (s)ubmit a voting
   (b)egin the voting
   (e)nd the voting
   submit a (v)ote
   b
   Enter VID:
   450215d32401d332a38359e75df7c553ff90d11ab59681011ec0df92b5ac7b0d
   [VE] Voting started, VID: 450215d32401d332a38359e75df7c553ff90d11ab59681011ec0df92b5ac7b0d

Now each voter can validate the voting description:

   python verify_voting_sig.py

::

   Input VDEH path (empty for default): ../voting_enclave/vdeh.tvp
   VE signature OK
   Input EH pubkey: 043b7deff1a4b00c52473a82da1a4e654be3137fe57e94b2225ed88195f414a15ae92b63a2d29729f23fa08c8238723be4d5a99b95e9b21abf372e0b698eff4d49
   EH signature OK
   VID: 450215d32401d332a38359e75df7c553ff90d11ab59681011ec0df92b5ac7b0d

and generate their votes:

   python voter.py

::

   Server public key: 0430fde09be72c4b5332ceb776ae0f8ebec6566298c5bd93d6a4cdce397ce0fd2f2d566b683bacca007fabd1f90759de3b71d2837e3a85fc460d53cc2cd0ba1489
   Input vid: 450215d32401d332a38359e75df7c553ff90d11ab59681011ec0df92b5ac7b0d
   Input option: 2
   Encrypted vote: 047cefc77ef993c2480677b8ac515a1beab406285811074a04f2e4eef971e3d2092f55696a03215e4627e2f881a25e6e5b1a10b852e2255a9c1f47cc52b7eb48d435b64b5d6852f07c961d4bef7eb3ed629e9fbeae690f6e3e2ae12a9862ec643773c8a2ff25fb4e2630d685ff11052a0129e2aa89df5cf95b1bf4fc17cd91f65045d60feeea254d2aa56a03dd72a09d2cf223bfb6cfe02f66fce3bd9f594f95788dfefc2475575f78efd47685cfdbdc89bcb9403a6647d4c985b015dc8050d8dc182ae40ef50d936743b4608d8ab6d93341fd4ae40d6bea3dd86975254a71efb9dcc6e6d876a8fbd7b10fd79148dea18bb781c11b5f7afe6ed5c2add81113e4c05b726716d7a61c20d3294171ecd8f630

After providing the necessary data it will generate a encrypted vote, which can be pasted into EH app.
::

   Enter a command:
   (s)ubmit a voting
   (b)egin the voting
   (e)nd the voting
   submit a (v)ote
   v
   Enter encrypted vote:
   047cefc77ef993c2480677b8ac515a1beab406285811074a04f2e4eef971e3d2092f55696a03215e4627e2f881a25e6e5b1a10b852e2255a9c1f47cc52b7eb48d435b64b5d6852f07c961d4bef7eb3ed629e9fbeae690f6e3e2ae12a9862ec643773c8a2ff25fb4e2630d685ff11052a0129e2aa89df5cf95b1bf4fc17cd91f65045d60feeea254d2aa56a03dd72a09d2cf223bfb6cfe02f66fce3bd9f594f95788dfefc2475575f78efd47685cfdbdc89bcb9403a6647d4c985b015dc8050d8dc182ae40ef50d936743b4608d8ab6d93341fd4ae40d6bea3dd86975254a71efb9dcc6e6d876a8fbd7b10fd79148dea18bb781c11b5f7afe6ed5c2add81113e4c05b726716d7a61c20d3294171ecd8f630
   Encrypted VVR: 3d7e99d03c822e7ca145ac60f8c99636dfe5e0b130593d1020cc4b9970d9306dec107f776c035a6f8f680b2e6133e148c0202c8e3793e18e18e67c50d7945d8e234e6a5b4108e9b80cd9d9b5efb6f16f675bbe128c4b0e1fe0d76d36ff9d4e613732d7026834b85a9bc0fb0d8d976f77f4df9aaed7ff4503a52388592ca35f769028f22e50ff8bd7d8f957c03a4b5d981071ac88a40e69b2c48fa8b01ab58ab9e344a7d2d5b5ddc746fbca3a2beaf551e10d9724e9e649491e795789df2b93213068aa5c77748dcc1a14213d9b6ac09c8f471a4ec06be1cb9cbd60635e982149

The EH app will return encrypted VVR which can be pasted into voter app for verification:
::

   Input VVR: 3d7e99d03c822e7ca145ac60f8c99636dfe5e0b130593d1020cc4b9970d9306dec107f776c035a6f8f680b2e6133e148c0202c8e3793e18e18e67c50d7945d8e234e6a5b4108e9b80cd9d9b5efb6f16f675bbe128c4b0e1fe0d76d36ff9d4e613732d7026834b85a9bc0fb0d8d976f77f4df9aaed7ff4503a52388592ca35f769028f22e50ff8bd7d8f957c03a4b5d981071ac88a40e69b2c48fa8b01ab58ab9e344a7d2d5b5ddc746fbca3a2beaf551e10d9724e9e649491e795789df2b93213068aa5c77748dcc1a14213d9b6ac09c8f471a4ec06be1cb9cbd60635e982149
   hash(rv): abb445eb0cbaebf955fd354aa430bdee4e5973650c15eae6d640831f014703d0
   Signature OK
   VVR voter public key OK (is ours)
   VVR VID OK
   VVR voter option OK
   VVR verified correctly

After submiting all of the votes you can end the voting:
::

   Enter a command:
   (s)ubmit a voting
   (b)egin the voting
   (e)nd the voting
   submit a (v)ote
   e
   Enter VID:
   450215d32401d332a38359e75df7c553ff90d11ab59681011ec0df92b5ac7b0d
   [VE] Voting stopped, VID: 450215d32401d332a38359e75df7c553ff90d11ab59681011ec0df92b5ac7b0d
   VREH:
   450215d32401d332a38359e75df7c553ff90d11ab59681011ec0df92b5ac7b0d0500000000000000010000000000000001000000000000000200000000000000abb445eb0cbaebf955fd354aa430bdee4e5973650c15eae6d640831f014703d0c23ef1c5dfde599c7caab1f3dc97349f491708a985bc79bacb22e62d7fc574d0dfd0a789c0c0b183191407e84593e23f968e6e517d81fa07fd2701d157585ebbf034bdf613f2b473a1d0a3544a0da118be9297b93537ed90e18e803ab194f1970a7f5c54bad7835f066d43f3dfef328455f689f65dcb210e7e3fce0e6484fcb3dcd20b027f4cdff2832adccbb68c37440ed2cc5f5299a3305bd1287d62fc04aa

Each voter can verify the results and that their vote was counted:

   python verify_voting_results.py

::

   Input VREH: 450215d32401d332a38359e75df7c553ff90d11ab59681011ec0df92b5ac7b0d0500000000000000010000000000000001000000000000000200000000000000abb445eb0cbaebf955fd354aa430bdee4e5973650c15eae6d640831f014703d0c23ef1c5dfde599c7caab1f3dc97349f491708a985bc79bacb22e62d7fc574d0dfd0a789c0c0b183191407e84593e23f968e6e517d81fa07fd2701d157585ebbf034bdf613f2b473a1d0a3544a0da118be9297b93537ed90e18e803ab194f1970a7f5c54bad7835f066d43f3dfef328455f689f65dcb210e7e3fce0e6484fcb3dcd20b027f4cdff2832adccbb68c37440ed2cc5f5299a3305bd1287d62fc04aa
   Input EH public key: 043b7deff1a4b00c52473a82da1a4e654be3137fe57e94b2225ed88195f414a15ae92b63a2d29729f23fa08c8238723be4d5a99b95e9b21abf372e0b698eff4d49
   VREH signature OK
   Inpute VE public key: 0430fde09be72c4b5332ceb776ae0f8ebec6566298c5bd93d6a4cdce397ce0fd2f2d566b683bacca007fabd1f90759de3b71d2837e3a85fc460d53cc2cd0ba1489
   VRVE signature OK
   Input VID: 450215d32401d332a38359e75df7c553ff90d11ab59681011ec0df92b5ac7b0d
   VID in VREH matches
   Input your RV hash: abb445eb0cbaebf955fd354aa430bdee4e5973650c15eae6d640831f014703d0
   Your vote was counted
   Voting results:
    1: 0
    2: 1
    3: 0
    4: 1
    5: 0

