# HandyStratum Documenation

- [Spec](spec.md)

##### Mask

To set HandyStratum to use a randomly generated mask per job, modify /lib/constants.js:15 ```constants.USE_MASK = false;``` value to ```true```;

[Read how and why mask can be utilized by a mining pool here](https://github.com/handshake-org/hsd/blob/master/lib/primitives/abstractblock.js#L368-L408)

How mask is generated in HandyStratum:
```
//lib/primitives.js:setAttemptMask(attempt,mask) (line 483)
pool  target: 0x000000ff00000000...
block target: 0x000000000000000f...
mask can be : 0x0000000XXXXXXXX0... (one of the X's will be set to a 1 randomly.)
```

##### Running HandyStratum

Example: /run.sh
```
#!/bin/bash
WALLET=hs1qwfpd5ukdwdew7tn7vdgtk0luglgckp3klj44f8
APIKEY=changeme_this_is_your_hsd_api_key
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

./node_modules/hsd/bin/hsd --network=$NETWORK --cors=true --api-key=$APIKEY \
--http-host=0.0.0.0 --coinbase-address=$WALLET \
--listen --plugins HandyStratum --stratum-host 0.0.0.0 \
--stratum-port 3008 --stratum-public-host 0.0.0.0 \
--stratum-public-port 3008 --stratum-max-inbound 1000 \
--stratum-difficulty 8 --stratum-dynamic \
--stratum-password=$STRATUMPASS \
--daemon
```