/*!
 * primitives.js - primitives for HandyStratum
 * Copyright (c) 2017-2018, Christopher Jeffrey (MIT License).
 * Copyright (c) 2019, Handshake Alliance (MIT License).
 * Copyright (c) 2021, HandyMiner: Alex Smith, Steven McKie, Thomas Costanzo (MIT License)
 * https://github.com/HandyMiner/HandyStratum
 */

"use strict";

const { StringDecoder } = require("string_decoder");
const { Lock } = require("bmutex");
const IP = require("binet");
const EventEmitter = require("events");
const { format } = require("util");
const assert = require("bsert");
const { BufferSet } = require("buffer-map");
const consensus = require("hsd/lib/protocol/consensus.js");
const common = require("hsd/lib/mining/common");
const BLAKE2b = require('bcrypto/lib/blake2b');

const util = require("./util.js");
const constants = require("./constants.js");
const SHARES_PER_MINUTE = constants.SHARES_PER_MINUTE;
const BAN_SCORE = constants.BAN_SCORE;

/**
 * Stratum Connection
 */

class Connection extends EventEmitter {
  /**
   * Create a stratum connection.
   * @constructor
   * @param {Stratum} stratum
   * @param {net.Socket} socket
   */

  constructor(stratum, socket) {
    super();

    this.locker = new Lock();
    this.stratum = stratum;
    this.logger = stratum.logger;
    this.socket = socket;
    this.host = IP.normalize(socket.remoteAddress);
    this.port = socket.remotePort;
    this.hostname = IP.toHostname(this.host, this.port);
    this.decoder = new StringDecoder("utf8");
    this.agent = "";
    this.recv = "";
    this.admin = false;
    this.users = new Set();
    this.sid = -1;
    this.difficulty = -1;
    this.nextDifficulty = -1;
    this.banScore = 0;
    this.lastBan = 0;
    this.drainSize = 0;
    this.destroyed = false;
    this.lastRetarget = -1;
    this.submissions = 0;
    this.prev = null;
    this.next = null;

    this._init();
  }

  _init() {
    this.on("packet", async msg => {
      try {
        await this.readPacket(msg);
      } catch (e) {
        this.error(e);
      }
    });

    this.socket.on("data", data => {
      this.feed(data);
    });

    this.socket.on("error", err => {
      this.emit("error", err);
    });

    this.socket.on("close", () => {
      this.logger.info("miner socket hung up.");
      //this.error("Socket hangup."); // this kills server?
      this.destroy();
    });

    this.socket.on("drain", () => {
      this.drainSize = 0;
    });
  }

  destroy() {
    if (this.destroyed) return;

    this.destroyed = true;

    this.locker.destroy();
    this.socket.destroy();
    this.socket = null;

    this.emit("close");
  }

  send(json) {
    if (this.destroyed) return;

    json = JSON.stringify(json);
    json += "\n";

    this.write(json);
  }

  write(text) {
    if (this.destroyed) return;

    if (this.socket.write(text, "utf8") === false) {
      this.drainSize += Buffer.byteLength(text, "utf8");
      if (this.drainSize > 5 << 20) {
        this.logger.warning("Client is not reading (%s).", this.id());
        this.destroy();
      }
    }
  }

  error(err) {
    if (this.destroyed) return;

    if (err instanceof Error) {
      err.message += ` (${this.id()})`;
      this.emit("error", err);
      return;
    }

    let msg = format.apply(null, arguments);

    msg += ` (${this.id()})`;

    this.emit("error", new Error(msg));
  }

  redirect() {
    const host = this.stratum.options.publicHost;
    const port = this.stratum.options.publicPort;

    const res = [
      "HTTP/1.1 200 OK",
      `X-Stratum: stratum+tcp://${host}:${port}`,
      "Connection: Close",
      "Content-Type: application/json; charset=utf-8",
      "Content-Length: 38",
      "",
      "",
      '{"error":null,"result":false,"id":0}'
    ];

    this.write(res.join("\r\n"));

    this.logger.debug("Redirecting client (%s).", this.id());

    this.destroy();
  }

  feed(data) {
    this.recv += this.decoder.write(data);

    if (this.recv.length >= 100000) {
      this.error("Too much data buffered (%s).", this.id());
      this.destroy();
      return;
    }

    if (/HTTP\/1\.1/i.test(this.recv)) {
      this.redirect();
      return;
    }

    const lines = this.recv.replace(/\r+/g, "").split(/\n+/);

    this.recv = lines.pop();

    for (const line of lines) {
      if (line.length === 0) continue;

      let msg;
      try {
        msg = ClientPacket.fromRaw(line);
      } catch (e) {
        this.error(e);
        continue;
      }

      this.emit("packet", msg);
    }
  }

  async readPacket(msg) {
    const unlock = await this.locker.lock();
    try {
      this.socket.pause();
      await this.handlePacket(msg);
    } finally {
      if (!this.destroyed) this.socket.resume();
      unlock();
    }
  }

  async handlePacket(msg) {
    return await this.stratum.handlePacket(this, msg);
  }

  addUser(username) {
    if (this.users.has(username)) return false;

    this.users.add(username);

    return true;
  }

  hasUser(username) {
    return this.users.has(username);
  }

  increaseBan(score) {
    const now = Date.now();

    this.banScore *= Math.pow(1 - 1 / 60000, now - this.lastBan);
    this.banScore += score;
    this.lastBan = now;

    if (this.banScore >= BAN_SCORE) {
      this.logger.debug(
        "Ban score exceeds threshold %d (%s).",
        this.banScore,
        this.id()
      );
      this.ban();
    }
  }

  ban() {
    this.emit("ban");
  }

  sendError(msg, code, reason) {
    this.logger.spam("Sending error %s (%s).", reason, this.id());

    this.send({
      id: msg.id,
      result: null,
      error: [code, reason, false]
    });
  }

  sendResponse(msg, result) {
    this.logger.spam("Sending response %s (%s).", msg.id, this.id());

    this.send({
      id: msg.id,
      result: result,
      error: null
    });
  }

  sendMethod(method, params) {
    this.logger.spam("Sending method %s (%s).", method, this.id());

    this.send({
      id: null,
      method: method,
      params: params
    });
  }

  sendDifficulty(difficulty) {
    assert(difficulty > 0, "Difficulty must be at least 1.");

    this.logger.debug(
      "Setting difficulty=%d for client (%s).",
      difficulty,
      this.id()
    );

    this.sendMethod("mining.set_difficulty", [difficulty]);
  }

  setDifficulty(difficulty) {
    this.nextDifficulty = difficulty;
  }

  sendJob(job) {
    this.logger.debug("Sending job %s to client (%s).", job.id, this.id());

    if (this.nextDifficulty !== -1) {
      this.submissions = 0;
      this.lastRetarget = Date.now();
      this.sendDifficulty(this.nextDifficulty);
      this.difficulty = this.nextDifficulty;
      this.nextDifficulty = -1;
    }

    this.sendMethod("mining.notify", job.toJSON());
  }

  retarget(max) {
    const now = Date.now();
    const pm = SHARES_PER_MINUTE;

    assert(this.difficulty > 0);
    assert(this.lastRetarget !== -1);

    this.submissions += 1;
    if (this.submissions % pm === 0) {
      const target = (this.submissions / pm) * 60000;
      let actual = now - this.lastRetarget;
      let difficulty = 0x100000000 / this.difficulty;

      if (max > -1 >>> 0) max = -1 >>> 0;
      if (Math.abs(target - actual) <= 5000) return false;

      if (actual < target / 4) actual = target / 4;

      if (actual > target * 4) actual = target * 4;

      difficulty *= actual;
      difficulty /= target;
      difficulty = 0x100000000 / difficulty;
      difficulty >>>= 0;
      difficulty = Math.min(max, difficulty);
      difficulty = Math.max(1, difficulty);
      this.setDifficulty(difficulty);

      return true;
    }

    return false;
  }

  id() {
    let id = this.host;

    if (this.agent) id += "/" + this.agent;

    return id;
  }
}

/**
 * ClientPacket
 */

class ClientPacket {
  /**
   * Create a packet.
   */

  constructor() {
    this.id = null;
    this.method = "unknown";
    this.params = [];
  }

  static fromRaw(json) {
    const packet = new ClientPacket();
    const msg = JSON.parse(json);

    if (msg.id != null) {
      assert(typeof msg.id === "string" || typeof msg.id === "number");
      packet.id = msg.id;
    }

    assert(typeof msg.method === "string");
    assert(msg.method.length <= 50);
    packet.method = msg.method;

    if (msg.params) {
      assert(Array.isArray(msg.params));
      packet.params = msg.params;
    }

    return packet;
  }
}

/**
 * Submission Packet
 */

class Submission {
  /**
   * Create a submission packet.
   */

  constructor() {
    this.username = "";
    this.job = "";
    this.nonce2 = 0;
    this.ts = 0;
    this.nonce = 0;
  }

  static fromPacket(msg) {
    const subm = new Submission();

    assert(msg.params.length >= 5, "Invalid parameters.");

    assert(util.isUsername(msg.params[0]), "Name must be a string.");
    assert(util.isJob(msg.params[1]), "Job ID must be a string.");

    assert(typeof msg.params[2] === "string", "Nonce2 must be a string.");
    assert(
      msg.params[2].length === constants.NONCE_SIZE * 2,
      "Nonce2 must be a string."
    );
    assert(util.isHex(msg.params[2]), "Nonce2 must be a string.");

    assert(typeof msg.params[3] === "string", "Time must be a string.");
    assert(msg.params[3].length === 8, "Time must be a string.");
    assert(util.isHex(msg.params[3]), "Time must be a string.");

    assert(typeof msg.params[4] === "string", "Nonce must be a string.");
    
    assert(util.isHex(msg.params[4]), "Nonce must be a string.");

    
    subm.username = msg.params[0];
    subm.job = msg.params[1];
    subm.nonce2 = parseInt(msg.params[2], 16);
    subm.ts = parseInt(msg.params[3], 16);
    subm.nonce = parseInt(msg.params[4],16);
    
    return subm;
  }
}

/**
 * Job
 */

class Job {
  /**
   * Create a job.
   * @constructor
   */

  constructor(id) {
    assert(typeof id === "string");

    this.id = id;
    this.attempt = null;
    this.target = consensus.ZERO_HASH;
    this.difficulty = constants.INITIAL_DIFFICULTY;
    this.submissions = new BufferSet();
    this.committed = false;
    this.prev = null;
    this.next = null;
  }

  fromTemplate(attempt) {
    this.attempt = attempt;
    //set mask randomly in a range of the target starts per every job
    // example:
    // share target: 0x000000ff00000000
    // block target: 0x000000000000000f
    // mask can be : 0x0000000XXXXXXXX0 (wherever we see an X can be mask pos)
    let mask = Buffer.alloc(32,0x00).toString('hex'); //init to all 0
    if(constants.USE_MASK){
      //if USE_MASK, generate the random mask
      mask = this.setAttemptMask(attempt,mask);
    }
    this.attempt.mask = Buffer.from(mask,'hex');
    console.log('set random mask for attempt',mask);
    this.attempt.refresh();
    this.target = attempt.target;
    this.difficulty = attempt.getDifficulty();
    return this;
  }
  setAttemptMask(attempt,mask){
    //set mask randomly in a range of the target starts per every job
    // example:
    // share target: 0x000000ff00000000
    // block target: 0x000000000000000f
    // mask can be : 0x0000000XXXXXXXX0 (wherever we see an X can  a 1 in the mask pos)
    const shareTargetBits = util.targetFromDifficulty(attempt.getDifficulty());
    const shareTarget = common.getTarget(shareTargetBits).toString('hex');
    const blockTarget = attempt.target.toString('hex');
  
    let startChar = -1;
    let endChar = -1;
    for(let i=0;i<shareTarget.length;i++){
      if(shareTarget[i] != '0' && startChar == -1){
        startChar = i+1;
      }
      if(blockTarget[i] != '0' && endChar == -1){
        endChar = i-1;
      }
    }
    if(startChar > endChar){
      //share diff is larger than block diff, maybe regtest/simnet/etc?
      //reverse them within the start/end of the targets
      let endTemp = startChar;
      startChar = endChar+1
      endChar = endTemp-1;
    }
    if(startChar <= 0){
      startChar = 1;
    }
    if(endChar <= 0){
      endChar = 2;
    }
    let maskLocation = Math.floor(Math.random() * (endChar - startChar + 1) + startChar);
    let maskChar = Math.floor(Math.random() * (15 - 1 + 1) + 1);

    mask = mask.substr(0,maskLocation) + maskChar.toString(16) + mask.substr(maskLocation+1);
    /*
    //leaving this in case you want to see how this works
    console.log('share target:',shareTarget);
    console.log('block target:',blockTarget);
    console.log('mask isset  :',mask.toString('hex'));
    */
    return mask;
  }

  static fromTemplate(id, attempt) {
    return new this(id).fromTemplate(attempt);
  }

  insert(hash) {
    if (this.submissions.has(hash)) return false;

    this.submissions.add(hash);
    return true;
  }

  check(nonce1, subm) {
    const nonce2 = subm.nonce2;
    const ts = subm.ts;
    const nonce = subm.nonce;//Buffer.from(subm.nonce,'hex');
    const exStr = Buffer.from(util.hex32(nonce1)+util.hex32(nonce2),'hex');
    let extraNonce = consensus.ZERO_NONCE;
    for(var i=0;i<exStr.length;i++){
      extraNonce[i] = exStr[i];
    }
    let mask = this.attempt.mask; //Buffer.from(subm.mask,'hex');
    this.attempt.extraNonce = extraNonce;
    const proof = this.attempt.getProof(nonce, ts, extraNonce, mask);
    return proof;
  }

  commit(share) {
    assert(!this.committed, "Already committed.");
    this.committed = true;
    return this.attempt.commit(share);
  }

  toJSON() {
    return [
      this.id,
      this.attempt.prevBlock.toString("hex"),
      this.attempt.merkleRoot.toString("hex"),
      this.attempt.witnessRoot.toString("hex"),
      this.attempt.treeRoot.toString("hex"),
      this.attempt.reservedRoot.toString("hex"),
      util.hex32(this.attempt.version),
      util.hex32(this.attempt.bits),
      util.hex32(this.attempt.time),
      BLAKE2b.multi(this.attempt.prevBlock, this.attempt.mask).toString('hex')
    ];
  }
}

module.exports.Connection = Connection;
module.exports.ClientPacket = ClientPacket;
module.exports.Submission = Submission;
module.exports.Job = Job;
