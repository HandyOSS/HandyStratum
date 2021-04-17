# HandyStratum Spec

HandyStratum follows a slightly modified version of stratum. Due to the slight differences in block headers between Handshake and Bitcoin, the stratum protocol needed to be changed.

This file contains the full spec of Handshake's stratum protocol.

## Server To Client Calls

- [mining.notify](#miningnotify)
- [mining.set_difficulty](#miningset_difficulty)


### mining.notify

```mining.notify(...)```

This is the primary call that differentiates Handshake's stratum protocol vs Bitcoin's.

mining.notify is used to notify the miner of the current job that it needs to process. The following are the fields that are returned in order.

1. Job ID - Used so that stratum can match shares with the client that mined them.
2. Hash of previous block - Needed in the header.
3. Merkle Tree - This is a list of merkle branches that are hashed along with the newly formed coinbase transaction to get the merkle root.
4. Witness Root - The witness root
5. Tree Root - The root of the Urkel tree that maintains name states. Needed for the block header.
6. Reserved Root - A root reserved for future use. Needed for block header.
7. Block Version - Needed for the block header.
8. nBits - Needed for the block header. This is the current network difficulty.
9. nTime - Needed for block header.
10. MaskHash - BLAKE2b.multi(PrevBlock, Mask) - The Mask hash that is needed for the block header. It prevents block withholding attacks by obfuscating the actual block target from the miner. Only the pool knows the mask. If constants.useMask is false, mask is ZERO_NONCE. [Read why mask can be utilized by a mining pool here](https://github.com/handshake-org/hsd/blob/master/lib/primitives/abstractblock.js#L368-L408) **Note: MaskHash is a key feature implemented by HandyMiner/HandyStratum. Our previous hstratum for pow_ng (blake2b+sha3) did not have mask implemented, and thus only 9 parameters. If HandyMiner sees the 10th parameter set, it will apply it as the .maskHash in the block template in the mining client. Mask Hash is optional and configured in lib/constants.js.**

### mining.set_difficulty

```mining.set_difficulty(difficulty)```

The server can adjust the difficulty required for miner shares with the "mining.set_difficulty" method. The miner should begin enforcing the new difficulty on the next job received. Some pools may force a new job out when set_difficulty is sent, using clean_jobs to force the miner to begin using the new difficulty immediately.


## Client To Server Calls

- [mining.authorize](#miningauthorize)
- [mining.subscribe](#miningsubscribe)
- [mining.submit](#miningsubmit)
- [mining.get_transactions](#miningget_transactions)
- [mining.authorize_admin](#miningauthorize_admin)
- [mining.add_user](#miningadd_user)

### mining.authorize

```mining.authorize("username", "password")```

This call is used to authorize a mining client with the server. It will return true if authorized.

### mining.subscribe

```mining.subscribe("user agent/version")```

This call subscribes the mining client to the pool to receive new jobs.

### mining.submit

```mining.submit("username", "job id", "ExtraNonce2", "nTime", "nOnce")```


This call is used to submit a share of work to the pool. The parameters are as follows:
1. The worker name.
2. Job ID
3. ExtraNonce2.
4. Time used in block header. Last 4 chars can&should be overflowed from the nonce.
5. nOnce.



### mining.get_transactions

```mining.get_transactions("job id")```

Server should send back an array with a hexdump of each transaction in the block specified for the given job id.

### mining.authorize_admin

```mining.authorize_admin("password")```

This call authorizes the admin to the pool. It only requires the admin password to be passed in.

### mining.add_user

```mining.add_user("username", "password")```

This call creates a new user that is capable of authorizing to the pool.
