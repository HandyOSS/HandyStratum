/*!
 * user.js - user object for HandyStratum server
 * Copyright (c) 2017-2018, Christopher Jeffrey (MIT License).
 * Copyright (c) 2019, Handshake Alliance (MIT License).
 * Copyright (c) 2021, HandyMiner: Alex Smith, Steven McKie, Thomas Costanzo (MIT License)
 * https://github.com/HandyMiner/HandyStratum
 */

"use strict";

const { consensus } = require("hsd");
const assert = require("bsert");
const hash256 = require("bcrypto/lib/hash256");

const util = require("./util.js");

/**
 * User
 */

class User {
  /**
   * Create a user.
   * @constructor
   * @param {Object} options
   */

  constructor(options) {
    this.username = "";
    this.password = consensus.ZERO_HASH;

    if (options) this.fromOptions(options);
  }

  fromOptions(options) {
    assert(options, "Options required.");
    assert(util.isUsername(options.username), "Username required.");
    assert(options.hash || options.password, "Password required.");

    this.setUsername(options.username);

    if (options.hash != null) this.setHash(options.hash);

    if (options.password != null) this.setPassword(options.password);

    return this;
  }

  static fromOptions(options) {
    return new this().fromOptions(options);
  }

  setUsername(username) {
    assert(util.isUsername(username), "Username must be a string.");
    this.username = username;
  }

  setHash(hash) {
    if (typeof hash === "string") {
      assert(util.isHex(hash), "Hash must be a hex string.");
      assert(hash.length === 64, "Hash must be 32 bytes.");
      this.password = Buffer.from(hash, "hex");
    } else {
      assert(Buffer.isBuffer(hash), "Hash must be a buffer.");
      assert(hash.length === 32, "Hash must be 32 bytes.");
      this.password = hash;
    }
  }

  setPassword(password) {
    assert(util.isPassword(password), "Password must be a string.");
    password = Buffer.from(password, "utf8");
    this.password = hash256.digest(password);
  }

  toJSON() {
    return {
      username: this.username,
      password: this.password.toString("hex")
    };
  }

  fromJSON(json) {
    assert(json);
    assert(typeof json.username === "string");
    this.username = json.username;
    this.setHash(json.password);
    return this;
  }

  static fromJSON(json) {
    return new this().fromJSON(json);
  }
}

module.exports = User;
