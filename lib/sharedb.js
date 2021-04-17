/*!
 * sharedb.js - share database for HandyStratum server
 * Copyright (c) 2017-2018, Christopher Jeffrey (MIT License).
 * Copyright (c) 2019, Handshake Alliance (MIT License).
 * Copyright (c) 2021, HandyMiner: Alex Smith, Steven McKie, Thomas Costanzo (MIT License)
 * https://github.com/HandyMiner/HandyStratum
 */

"use strict";

const assert = require("bsert");
const fs = require("bfile");
const path = require("path");

const util = require("./util.js");

/**
 * Share DB
 */

class ShareDB {
  /**
   * Create a Share DB
   * @constructor
   * @param {Object} options
   */

  constructor(options) {
    this.network = options.network;
    this.logger = options.logger;
    this.location = path.resolve(options.prefix, "shares");

    this.map = Object.create(null);
    this.total = 0;
    this.size = 0;
  }

  async open() {
    await fs.mkdirp(this.location);
  }

  async close() {}

  file(entry) {
    const name = entry.height + "-" + entry.hash.toString('hex');
    return path.resolve(this.location, name + ".json");
  }

  add(username, difficulty) {
    if (!this.map[username]) {
      this.map[username] = 0;
      this.size++;
    }

    this.map[username] += difficulty;
    this.total += difficulty;
  }

  clear() {
    this.map = Object.create(null);
    this.size = 0;
    this.total = 0;
  }

  async commit(entry, block) {
    const cb = block.txs[0];
    const addr = cb.outputs[0].getAddress();

    assert(addr);
    const data = {
      network: this.network.type,
      height: entry.height,
      block: block.hash.toString('hex'),
      ts: block.ts,
      time: util.now(),
      txid: cb.txid(),
      address: addr.toString(this.network),
      reward: cb.getOutputValue(),
      size: this.size,
      total: this.total,
      shares: this.map
    };

    this.clear();

    const file = this.file(entry);
    const json = JSON.stringify(data, null, 2);

    this.logger.info(
      "Committing %d payouts to disk for block %d (file=%s).",
      data.size,
      entry.height,
      file
    );

    await fs.writeFile(file, json);
  }
}

module.exports = ShareDB;
