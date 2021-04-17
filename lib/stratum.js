/*!
 * stratum.js - stratum server for hsd
 * Copyright (c) 2017-2018, Christopher Jeffrey (MIT License).
 * Copyright (c) 2019, Handshake Alliance (MIT License).
 * Copyright (c) 2021, HandyMiner: Alex Smith, Steven McKie, Thomas Costanzo (MIT License)
 * https://github.com/HandyMiner/HandyStratum
 */

"use strict";

const assert = require("bsert");
const path = require("path");
const os = require("os");
const EventEmitter = require("events");
const { Lock } = require("bmutex");
const tcp = require("btcp");
const IP = require("binet");
const Logger = require("blgr");
const List = require("blst");
const hash256 = require("bcrypto/lib/hash256");
const { safeEqual } = require("bcrypto/lib/safe");
const { Network } = require("hsd");
const common = require("hsd/lib/mining/common");

const ShareDB = require("./sharedb");
const UserDB = require("./userdb");
const { Connection, Job, Submission } = require("./primitives");

const constants = require("./constants");
const util = require("./util.js");

/**
 * Stratum Server
 * @extends {EventEmitter}
 */

class Stratum extends EventEmitter {
  /**
   * Create a stratum server.
   * @constructor
   * @param {Object} options
   */

  constructor(options) {
    super();

    this.options = new StratumOptions(options);

    this.node = this.options.node;
    this.chain = this.options.chain;
    this.network = this.options.network;
    this.logger = this.options.logger.context("stratum");
    this.difficulty = this.options.difficulty;

    this.server = tcp.createServer();
    this.sharedb = new ShareDB(this.options);
    this.userdb = new UserDB(this.options);
    this.locker = new Lock();
    this.jobMap = new Map();
    this.banned = new Map();
    this.jobs = new List();
    this.current = null;
    this.inbound = new List();
    this.lastActive = 0;
    this.subscribed = false;
    this.uid = 0;
    this.suid = 0;

    this._init();
  }

  sid() {
    const sid = this.suid;
    this.suid += 1;
    this.suid >>>= 0;
    return sid;
  }

  jid() {
    const now = util.now();
    const id = this.uid;
    this.uid += 1;
    this.uid >>>= 0;
    return `${now}:${id}`;
  }

  _init() {
    this.server.on("connection", socket => {
      this.handleSocket(socket);
      socket.on('error',socketErr=>{
        this.logger.info('stratum caught socket error %s',socketErr);
      })
    });
    this.server.on('error',socketErr=>{
      this.logger.info('stratum caught socket error %s',socketErr);
    })

    this.node.on("connect", async () => {
      try {
        await this.handleBlock();
      } catch (e) {
        this.emit("error", e);
      }
    });

    this.node.on("tx", async () => {
      try {
        await this.handleTX();
      } catch (e) {
        this.emit("error", e);
      }
    });
  }

  async handleBlock() {
    const unlock = await this.locker.lock();
    try {
      return await this._handleBlock();
    } finally {
      unlock();
    }
  }

  async _handleBlock() {
    const now = util.now();

    if (!this.subscribed) {
      this.lastActive = now;
      return;
    }

    this.current = null;
    this.lastActive = now;

    await this.notifyAll();
  }

  async handleTX() {
    const unlock = await this.locker.lock();
    try {
      return await this._handleTX();
    } finally {
      unlock();
    }
  }

  async _handleTX() {
    const now = util.now();

    if (!this.subscribed) {
      this.lastActive = now;
      return;
    }

    if (now > this.lastActive + constants.ACTIVE_TIME) {
      this.current = null;
      this.lastActive = now;

      await this.notifyAll();
    }
  }

  async handleSocket(socket) {
    if (!socket.remoteAddress) {
      this.logger.debug("Ignoring disconnected client.");
      socket.destroy();
      return;
    }

    const host = IP.normalize(socket.remoteAddress);

    if (this.inbound.size >= this.options.maxInbound) {
      this.logger.debug("Ignoring client: too many inbound (%s).", host);
      socket.destroy();
      return;
    }

    if (this.isBanned(host)) {
      this.logger.debug("Ignoring banned client (%s).", host);
      socket.destroy();
      return;
    }

    socket.setKeepAlive(true);
    socket.setNoDelay(true);

    this.addClient(socket);
  }

  addClient(socket) {
    const conn = new Connection(this, socket);

    conn.on("error", err => {
      this.logger.info("stratum client conn error",err);
    });

    conn.on("close", () => {
      assert(this.inbound.remove(conn));
    });

    conn.on("ban", () => {
      this.handleBan(conn);
    });

    this.inbound.push(conn);
  }

  handleBan(conn) {
    this.logger.warning("Banning client (%s).", conn.id());
    this.banned.set(conn.host, util.now());
    conn.destroy();
  }

  isBanned(host) {
    const time = this.banned.get(host);

    if (time == null) return false;

    if (util.now() - time > constants.BAN_TIME) {
      this.banned.delete(host);
      return false;
    }

    return true;
  }

  async listen() {
    this.server.maxConnections = this.options.maxInbound;

    await this.server.listen(this.options.port, this.options.host);

    this.logger.info("Server listening on %d.", this.options.port);
  }

  async open() {
    if (this.node.miner.addresses.length === 0)
      throw new Error("No addresses available for coinbase.");

    await this.userdb.open();
    await this.sharedb.open();
    await this.listen();

    if (this.options.password) {
      if (!this.userdb.get("admin")) {
        this.userdb.add({
          username: "admin",
          hash: this.options.password
        });
      }
    }

    this.lastActive = util.now();
  }

  async close() {
    let conn, next;

    for (conn = this.inbound.head; conn; conn = next) {
      next = conn.next;
      conn.destroy();
    }

    await this.server.close();
    await this.userdb.close();
    await this.sharedb.close();
  }

  async notifyAll() {
    const job = await this.getJob();
    let conn;

    this.logger.debug("Notifying all clients of new job: %s.", job.id);

    for (conn = this.inbound.head; conn; conn = conn.next) {
      if (conn.sid === -1) continue;

      conn.sendJob(job);
    }
  }

  createBlock() {
    if (this.node.miner.addresses.length === 0)
      throw new Error("No addresses available for coinbase.");

    return this.node.miner.createBlock();
  }

  addJob(job) {
    if (this.jobs.size >= constants.MAX_JOBS) this.removeJob(this.jobs.head);

    assert(this.jobs.push(job));

    assert(!this.jobMap.has(job.id));
    this.jobMap.set(job.id, job);

    this.current = job;
  }

  removeJob(job) {
    assert(this.jobs.remove(job));

    assert(this.jobMap.has(job.id));
    this.jobMap.delete(job.id);

    if (job === this.current) this.current = null;
  }

  async getJob() {
    if (!this.current) {
      const attempt = await this.createBlock();
      const job = Job.fromTemplate(this.jid(), attempt);

      this.addJob(job);

      this.logger.debug(
        "New job (id=%s, prev=%s).",
        job.id,
        job.attempt.prevBlock.toString("hex")
      );
    }

    return this.current;
  }

  async tryCommit(entry, block) {
    try {
      await this.sharedb.commit(entry, block);
    } catch (e) {
      this.emit("error", e);
    }
  }

  auth(username, password) {
    const user = this.userdb.get(username);

    if (!user) return false;

    const passwd = Buffer.from(password, "utf8");
    const hash = hash256.digest(passwd);

    if (!safeEqual(hash, user.password)) return false;

    return true;
  }

  authAdmin(password) {
    if (!this.options.password) return false;

    const data = Buffer.from(password, "utf8");
    const hash = hash256.digest(data);

    if (!safeEqual(hash, this.options.password)) return false;

    return true;
  }

  async addBlock(conn, block) {
    // Broadcast immediately.
    this.node.broadcast(block);

    let entry;
    try {
      entry = await this.chain.add(block);
    } catch (e) {
      if (e.type === "VerifyError") {
        switch (e.reason) {
          case "high-hash":
            return new StratumError(23, "high-hash");
          case "duplicate":
            return new StratumError(22, "duplicate");
        }
        return new StratumError(20, e.reason);
      }
      throw e;
    }

    if (!entry) return new StratumError(21, "stale-prevblk");

    if (entry.hash !== this.chain.tip.hash)
      return new StratumError(21, "stale-work");

    this.tryCommit(entry, block);

    this.logger.info(
      "Client found block %s (%d) (%s).",
      entry.height,//entry.rhash(),
      entry.height,
      conn.id()
    );

    return null;
  }

  async handlePacket(conn, msg) {
    const unlock = await this.locker.lock();
    try {
      return await this._handlePacket(conn, msg);
    } finally {
      unlock();
    }
  }

  async _handlePacket(conn, msg) {
    switch (msg.method) {
      case "mining.authorize":
        return this.handleAuthorize(conn, msg);
      case "mining.subscribe":
        return this.handleSubscribe(conn, msg);
      case "mining.submit":
        return this.handleSubmit(conn, msg);
      case "mining.get_transactions":
        return this.handleTransactions(conn, msg);
      case "mining.authorize_admin":
        return this.handleAuthAdmin(conn, msg);
      case "mining.add_user":
        return this.handleAddUser(conn, msg);
      default:
        return this.handleUnknown(conn, msg);
    }
  }

  async handleAuthorize(conn, msg) {
    if (typeof msg.params.length < 2) {
      conn.sendError(msg, 0, "invalid params");
      return;
    }

    const user = msg.params[0];
    const pass = msg.params[1];

    if (!util.isUsername(user) || !util.isPassword(pass)) {
      conn.sendError(msg, 0, "invalid params");
      return;
    }

    if (!this.auth(user, pass)) {
      this.logger.debug(
        "Client failed auth for user %s (%s).",
        user,
        conn.id()
      );
      conn.sendResponse(msg, false);
      return;
    }

    this.logger.debug(
      "Client successfully authd for %s (%s).",
      user,
      conn.id()
    );

    conn.addUser(user);
    conn.sendResponse(msg, true);
  }

  async handleSubscribe(conn, msg) {
    if (!this.chain.synced) {
      conn.sendError(msg, 0, "not up to date");
      return;
    }

    if (!conn.agent && msg.params.length > 0) {
      if (!util.isAgent(msg.params[0])) {
        conn.sendError(msg, 0, "invalid params");
        return;
      }
      conn.agent = msg.params[0];
    }

    if (msg.params.length > 1) {
      if (!util.isSID(msg.params[1])) {
        conn.sendError(msg, 0, "invalid params");
        return;
      }
      conn.sid = this.sid();
    } else {
      conn.sid = this.sid();
    }

    if (!this.subscribed) {
      this.logger.debug("First subscriber (%s).", conn.id());
      this.subscribed = true;
    }

    const sid = util.hex32(conn.sid);
    const job = await this.getJob();

    this.logger.debug(
      "Client is subscribing with sid=%s (%s).",
      sid,
      conn.id()
    );

    conn.sendResponse(msg, [
      [["mining.notify", sid], ["mining.set_difficulty", sid]],
      sid,
      constants.NONCE_SIZE
    ]);

    conn.setDifficulty(this.difficulty);
    conn.sendJob(job);
  }

  async handleSubmit(conn, msg) {
    const now = this.network.now();

    let subm;
    try {
      subm = Submission.fromPacket(msg);
    } catch (e) {
      conn.sendError(msg, 0, "invalid params");
      return;
    }

    this.logger.spam("Client submitted job %s (%s).", subm.job, conn.id());

    if (!conn.hasUser(subm.username)) {
      conn.sendError(msg, 24, "unauthorized user");
      return;
    }

    if (conn.sid === -1) {
      conn.sendError(msg, 25, "not subscribed");
      return;
    }

    const job = this.jobMap.get(subm.job);

    if (!job || job.committed) {
      conn.sendError(msg, 21, "job not found");
      return;
    }

    if (job !== this.current) {
      this.logger.warning(
        "Client is submitting a stale job %s (%s).",
        job.id,
        conn.id()
      );
    }

    // Non-consensus sanity check.
    // 2 hours should be less than MTP in 99% of cases.
    //not helpful in real life or testing for that matter
    /*if (subm.ts < now - 7200) {
      conn.sendError(msg, 20, "time too old");
      return;
    }

    if (subm.ts > now + 7200) {
      conn.sendError(msg, 20, "time too new");
      return;
    }*/

    const share = job.check(conn.sid, subm);
   
    const shareTargetBits = util.targetFromDifficulty(conn.difficulty);
    let shareTarget = common.getTarget(shareTargetBits);
    let OGPoolDiff = job.target;//diffTarget;
    const difficulty = common.getDifficulty(share.powHash());
    
    let hash = share.powHash();
    
    if(hash.compare(OGPoolDiff) > 0 && hash.compare(shareTarget) > 0){
      this.logger.debug(
        "Client submitted a low share of %d, hash=%s, ban=%d (%s).",
        difficulty,
        hash.toString('hex'),
        conn.banScore,
        conn.id()
      );

      conn.increaseBan(1);
      conn.sendError(msg, 23, "high-hash");
      conn.sendDifficulty(conn.difficulty);

      return;
    }

    if (!job.insert(hash)) {
      this.logger.debug(
        "Client submitted a duplicate share: %s (%s).",
        entry.height,//share.rhash(),
        conn.id()
      );
      conn.increaseBan(10);
      conn.sendError(msg, 22, "duplicate");
      return;
    }

    this.sharedb.add(subm.username, difficulty);

    this.logger.debug(
      "Client submitted share of %d, hash=%s (%s).",
      difficulty,
      hash.toString('hex'),//share.rhash(),
      conn.id()
    );

    let error;

    if (hash.compare(OGPoolDiff) <= 0) {
      this.logger.debug('share hash   %s',share.shareHash().toString('hex'));
      this.logger.debug('og target    %s',OGPoolDiff.toString('hex'));
      this.logger.debug('share target %s',shareTarget.toString('hex'));
      this.logger.debug('share pow    %s',share.powHash().toString('hex'));
      this.logger.debug('un-masked    %s',hash.toString('hex'));
      const block = job.commit(share);
      error = await this.addBlock(conn, block);
    }
    else{
      this.logger.warning("didnt verify share vs block target. share %s  target %s",hash.toString('hex'),job.target.toString('hex'));
      this.logger.debug('share hash   %s',share.shareHash().toString('hex'));
      this.logger.debug('og target    %s',OGPoolDiff.toString('hex'));
      this.logger.debug('share target %s',shareTarget.toString('hex'));
      this.logger.debug('share pow    %s',share.powHash().toString('hex'));
      this.logger.debug('un-masked    %s',hash.toString('hex'));
    }

    if (error) {
      this.logger.warning(
        "Client found an invalid block: %s (%s).",
        error.reason,
        conn.id()
      );
      conn.sendError(msg, error.code, error.reason);
    } else {
      conn.sendResponse(msg, true);
    }

    if (this.options.dynamic) {
      if (conn.retarget(job.difficulty)) {
        this.logger.debug(
          "Retargeted client to %d (%s).",
          conn.nextDifficulty,
          conn.id()
        );
        conn.sendDifficulty(conn.nextDifficulty);
      }
    }
  }

  async handleTransactions(conn, msg) {
    if (conn.sid === -1) {
      conn.sendError(msg, 25, "not subscribed");
      return;
    }

    if (msg.params.length < 1) {
      conn.sendError(msg, 21, "job not found");
      return;
    }

    const id = msg.params[0];

    if (!util.isJob(id)) {
      conn.sendError(msg, 21, "job not found");
      return;
    }

    const job = this.jobMap.get(id);

    if (!job || job.committed) {
      conn.sendError(msg, 21, "job not found");
      return;
    }

    this.logger.debug("Sending tx list (%s).", conn.id());

    const attempt = job.attempt;
    const result = [];

    for (const item of attempt.items)
      result.push(item.tx.hash().toString("hex"));

    conn.sendResponse(msg, result);
  }

  async handleAuthAdmin(conn, msg) {
    if (typeof msg.params.length < 1) {
      conn.sendError(msg, 0, "invalid params");
      return;
    }

    const password = msg.params[0];

    if (!util.isPassword(password)) {
      conn.sendError(msg, 0, "invalid params");
      return;
    }

    if (!this.authAdmin(password)) {
      this.logger.debug("Client sent bad admin password (%s).", conn.id());
      conn.increaseBan(10);
      conn.sendError(msg, 0, "invalid password");
      return;
    }

    conn.admin = true;
    conn.sendResponse(msg, true);
  }

  async handleAddUser(conn, msg) {
    if (typeof msg.params.length < 3) {
      conn.sendError(msg, 0, "invalid params");
      return;
    }

    const user = msg.params[0];
    const pass = msg.params[1];

    if (!util.isUsername(user) || !util.isPassword(pass)) {
      conn.sendError(msg, 0, "invalid params");
      return;
    }

    /*

    //not needed for un-registered/anonymous stratum. 
    //If needed, re-enable this and have admin functions to add new users
    if (!conn.admin) {
      this.logger.debug("Client is not an admin (%s).", conn.id());
      conn.sendError(msg, 0, "only admin can add user");
      return;
    }

    */

    try {
      this.userdb.add({
        username: user,
        password: pass
      });
    } catch (e) {
      conn.sendError(msg, 0, e.message);
      return;
    }

    conn.sendResponse(msg, true);
  }

  async handleUnknown(conn, msg) {
    this.logger.debug("Client sent an unknown message (%s):", conn.id());

    this.logger.debug(msg);

    conn.send({
      id: msg.id,
      result: null,
      error: true
    });
  }
}

Stratum.id = "stratum";

/**
 * Stratum Options
 */

class StratumOptions {
  /**
   * Create stratum options.
   * @constructor
   * @param {Object} options
   */

  constructor(options) {
    this.node = null;
    this.chain = null;
    this.logger = Logger.global;
    this.network = Network.primary;
    this.host = "0.0.0.0";
    this.port = 3008;
    this.publicHost = "127.0.0.1";
    this.publicPort = 3008;
    this.maxInbound = 50;
    this.difficulty = constants.INITIAL_DIFFICULTY;
    this.dynamic = true;
    this.prefix = path.resolve(os.homedir(), ".hsd", "stratum");
    this.password = null;

    this.fromOptions(options);
  }

  fromOptions(options) {
    assert(options, "Options are required.");
    assert(
      options.node && typeof options.node === "object",
      "Node is required."
    );

    this.node = options.node;
    this.chain = this.node.chain;
    this.network = this.node.network;
    this.logger = this.node.logger;
    this.prefix = this.node.location("stratum");

    if (options.host != null) {
      assert(typeof options.host === "string");
      this.host = options.host;
    }

    if (options.port != null) {
      assert(typeof options.port === "number");
      this.port = options.port;
    }

    if (options.publicHost != null) {
      assert(typeof options.publicHost === "string");
      this.publicHost = options.publicHost;
    }

    if (options.publicPort != null) {
      assert(typeof options.publicPort === "number");
      this.publicPort = options.publicPort;
    }

    if (options.maxInbound != null) {
      assert(typeof options.maxInbound === "number");
      this.maxInbound = options.maxInbound;
    }

    if (options.difficulty != null) {
      assert(typeof options.difficulty === "number");
      this.difficulty = options.difficulty;
    }

    if (options.dynamic != null) {
      assert(typeof options.dynamic === "boolean");
      this.dynamic = options.dynamic;
    }

    if (options.password != null) {
      assert(util.isPassword(options.password));
      this.password = hash256.digest(Buffer.from(options.password, "utf8"));
    }

    return this;
  }

  static fromOptions(options) {
    return new this().fromOptions(options);
  }
}

/**
 * Stratum Error
 */

class StratumError {
  /**
   * Create a stratum error.
   * @constructor
   * @param {Number} code
   * @param {String} reason
   */

  constructor(code, reason) {
    this.code = code;
    this.reason = reason;
  }
}

/*
 * Expose
 */

module.exports = Stratum;
