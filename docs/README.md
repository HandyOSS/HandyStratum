# HandyStratum Documenation

- [Spec](spec.md)

##### Mask

To set HandyStratum to use a randomly generated mask per job, modify /lib/constants.js:15 ```constants.USE_MASK = false;``` (default=false) value to ```true```;

[Read how and why mask can be utilized by a mining pool for Handshake here](https://github.com/handshake-org/hsd/blob/master/lib/primitives/abstractblock.js#L368-L408)

How mask is generated in HandyStratum:
```
//lib/primitives.js:setAttemptMask(attempt,mask) (line 483)
pool  target: 0x000000ff00000000...
block target: 0x000000000000000f...
mask can be : 0x0000000XXXXXXXX0... (one of the X's will be set to a 1 randomly.)
```
Thus the mask is built into the block header and obfuscated from the mining client as the mining client is returned the maskHash ( Blake2b.multi(previousBlock,mask) ) for the block header creation on the client.

##### Running HandyStratum
HandyStratum runs as a plugin to hsd. Simply install it in your hsd directory ```npm install HandyStratum``` and run it like:

```Example: /run.sh```
Note: --stratum-difficulty 8. This is pretty reasonable for an hs1, maybe a tad low for an hs1-plus but allows it time to ramp up with variable diff. I would recommend having a second instance running on another port with a much higher initial diff specifically for hs3/hs5 (TH scale asics).
```
#!/bin/bash
WALLET=hs1qwfpd5ukdwdew7tn7vdgtk0luglgckp3klj44f8
APIKEY=changeme_this_is_your_hsd_node_api_key
STRATUMPASS=stratum_admin_password
NETWORK=simnet
if [ $1 ]
then
	WALLET=$1
fi
if [ $2 ]
then
	NETWORK=$2
fi
if [ $3 ]
then
	APIKEY=$3
fi

if [ $4 ]
then
	STRATUMPASS=$4
fi

./node_modules/hsd/bin/hsd \
--network=$NETWORK \
--cors=true \
--api-key=$APIKEY \
--http-host=0.0.0.0 \
--coinbase-address=$WALLET \
--listen \
--plugins HandyStratum \
--stratum-host 0.0.0.0 \
--stratum-port 3008 \
--stratum-public-host 0.0.0.0 \
--stratum-public-port 3008 \
--stratum-max-inbound 1000 \
--stratum-difficulty 8 \
--stratum-dynamic \
--stratum-password=$STRATUMPASS \
--daemon
```