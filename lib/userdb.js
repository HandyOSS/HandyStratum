/*!
 * userdb.js - user database for HandyStratum server
 * Copyright (c) 2017-2018, Christopher Jeffrey (MIT License).
 * Copyright (c) 2019, Handshake Alliance (MIT License).
 * Copyright (c) 2021, HandyMiner: Alex Smith, Steven McKie, Thomas Costanzo (MIT License)
 * https://github.com/HandyMiner/HandyStratum
 */

"use strict";

const assert = require("bsert");
const fs = require("bfile");
const path = require("path");
const { Lock } = require("bmutex");

const User = require("./user.js");
const util = require("./util.js");

/**
 * User DB
 */

class UserDB {
  /**
   * Create a user DB.
   * @constructor
   * @param {Object} options
   */

  constructor(options) {
    this.network = options.network;
    this.logger = options.logger;
    this.location = path.resolve(options.prefix, "users.json");
    this.locker = new Lock();
    this.lastFail = 0;
    this.stream = null;

    this.map = new Map();
    this.size = 0;
  }

  async open() {
    const unlock = await this.locker.lock();
    try {
      return await this._open();
    } finally {
      unlock();
    }
  }

  async _open() {
    await this.load();
  }

  async close() {
    const unlock = await this.locker.lock();
    try {
      return await this._close();
    } finally {
      unlock();
    }
  }

  async _close() {
    if (!this.stream) return;

    try {
      this.stream.close();
    } catch (e) {}

    this.stream = null;
  }

  load() {
    return new Promise((resolve, reject) => {
      this._load(resolve, reject);
    });
  }

  _load(resolve, reject) {
    let buf = "";
    let lineno = 0;

    let stream = fs.createReadStream(this.location, {
      flags: "r",
      encoding: "utf8",
      autoClose: true
    });

    const close = () => {
      if (!stream) return;

      try {
        stream.close();
      } catch (e) {}

      stream = null;
    };

    stream.on("error", err => {
      if (!stream) return;

      if (err.code === "ENOENT") {
        close();
        resolve();
        return;
      }

      close();
      reject(err);
    });

    stream.on("data", data => {
      if (!stream) return;

      buf += data;

      if (buf.length >= 1000000) {
        close();
        reject(new Error(`UserDB parse error. Line: ${lineno}.`));
        return;
      }

      const lines = buf.split(/\n+/);

      buf = lines.pop();

      for (const line of lines) {
        lineno += 1;

        if (line.length === 0) continue;

        let json, user;
        try {
          json = JSON.parse(line);
          user = User.fromJSON(json);
        } catch (e) {
          close();
          reject(new Error(`UserDB parse error. Line: ${lineno}.`));
          return;
        }

        if (!this.map.has(user.username)) this.size += 1;

        this.map.set(user.username, user);
      }
    });

    stream.on("end", () => {
      if (!stream) return;

      this.logger.debug("Loaded %d users into memory.", this.size);

      stream = null;
      resolve();
    });
  }

  get(username) {
    return this.map.get(username);
  }

  has(username) {
    return this.map.has(username);
  }

  add(options) {
    const user = new User(options);

    assert(!this.map.has(user.username), "User already exists.");

    this.logger.debug("Adding new user (%s).", user.username);

    this.map.set(user.username, user);
    this.size += 1;

    this.write(user.toJSON());
  }

  setPassword(username, password) {
    const user = this.map.get(username);
    assert(user, "User does not exist.");
    user.setPassword(password);
    this.write(user.toJSON());
  }

  write(data) {
    const stream = this.getStream();

    if (!stream) return;

    const json = JSON.stringify(data) + "\n";
    stream.write(json, "utf8");
  }

  getStream() {
    if (this.stream) return this.stream;

    if (this.lastFail > util.now() - 10) return null;

    this.lastFail = 0;

    this.stream = fs.createWriteStream(this.location, { flags: "a" });

    this.stream.on("error", err => {
      this.logger.warning("UserDB file stream died!");
      this.logger.error(err);

      try {
        this.stream.close();
      } catch (e) {}

      // Retry in ten seconds.
      this.stream = null;
      this.lastFail = util.now();
    });

    return this.stream;
  }
}

module.exports = UserDB;
