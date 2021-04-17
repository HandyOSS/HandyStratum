# HandyStratum

A segwit-capable stratum server on top of [hsd][hsd]. This is a hsd
plugin which will run a stratum server in the same process as a hsd fullnode.

**HandyMiner Team Donation Address (HNS): ```hs1qwfpd5ukdwdew7tn7vdgtk0luglgckp3klj44f8```**

**HandyMiner Team Donation Address (BTC): ```bc1qk3rk4kgek0hzpgs8qj4yej9j5fs7kcnjk7kuvt```**

## Usage

HandyStratum can be used as a hsd plugin.

Simply ```npm install HandyStratum``` within your hsd directory and run like:

``` bash
$ hsd --plugins HandyStratum \
  --stratum-host :: \
  --stratum-port 3008 \
  --stratum-public-host pool.example.com \
  --stratum-public-port 3008 \
  --stratum-max-inbound 1000 \
  --stratum-difficulty 8 \
  --stratum-dynamic \
  --stratum-password=admin-pass
  --daemon
```

Additional notes on running/configuration can be found in (./docs/README.md)[./docs/README.md] and an example shell script is in (./run.sh)[./run.sh]

## Cutting out the middleman

While having a stratum+fullnode marriage violates separation of concerns, it
provides a benefit to large competitive miners: because it sits in the same
process, there is no overhead of hitting/longpolling a JSON-rpc api to submit
or be notified of new blocks. It has direct in-memory access to all of the data
it needs. No getwork or getblocktemplate required.

It can also broadcast submitted blocks before verifying and saving them to disk
(since we created the block and know it's going to be valid ahead of time).

### Single point of failure?

There's nothing to say you can't have multiple hsd-nodes/stratum-servers
behind a reverse/failover proxy still. It's only a single point of failure if
you treat it that way.

## Payouts

Shares are currently tracked by username and will be dumped to
`~/.hsd/stratum/shares/[height]-[hash].json` when a block is found. A script
can parse through these later and either add the user's balance to a webserver
or pay directly to an address. Users are stored in a line-separated json file
in `~/.hsd/stratum/users.json`.

## Administration

HandyStratum exposes some custom stratum calls:
`mining.authorize_admin('password')` to auth as an admin and
`mining.add_user('username', 'password')` to create a user during runtime.

## Contribution and License Agreement

If you contribute code to this project, you are implicitly allowing your code
to be distributed under the MIT license. You are also implicitly verifying that
all code is your original work. `</legalese>`

## License

Copyright (c) 2017-2018, Christopher Jeffrey (MIT License).
Copyright (c) 2019, Handshake Alliance (MIT License).
Copyright (c) 2021, HandyMiner: Alex Smith, Steven McKie, Thomas Costanzo (MIT License)

See LICENSE for more info.

[hsd]: https://github.com/hsd-org/hsd
[HandyMiner-Goldshell-CLI]: https://github.com/HandyMiner/HandyMiner-Goldshell-CLI
[HandyMiner-Goldshell-GUI]: https://github.com/HandyMiner/HandyMiner-Goldshell-GUI
