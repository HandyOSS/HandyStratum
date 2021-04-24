#!/bin/bash
WALLET=hs1qwfpd5ukdwdew7tn7vdgtk0luglgckp3klj44f8
APIKEY=earthlab #changeme
STRATUMPASS=earthlab
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
--http-host=0.0.0.0 --coinbase-address=$WALLET --index-address=true \
--index-tx=true --listen --plugins handystratum --stratum-host 0.0.0.0 \
--stratum-port 3008 --stratum-public-host 0.0.0.0 \
--stratum-public-port 3008 --stratum-max-inbound 1000 \
--stratum-difficulty 8 --stratum-dynamic \
--stratum-password=$STRATUMPASS
