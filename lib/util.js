/*!
 * util.js - util functions for HandyStratum server
 * Copyright (c) 2017-2018, Christopher Jeffrey (MIT License).
 * Copyright (c) 2019, Handshake Alliance (MIT License).
 * Copyright (c) 2021, HandyMiner: Alex Smith, Steven McKie, Thomas Costanzo (MIT License)
 * https://github.com/HandyMiner/HandyStratum
 */

"use strict";

const assert = require("bsert");
const BN = require('bn.js');
const { consensus } = require("hsd");

/**
 * @exports util
 */

const util = exports;

util.now = function now() {
  return Math.floor(Date.now() / 1000);
};

util.isUsername = function isUsername(username) {
  if (typeof username !== "string") return false;

  return username.length > 0 && username.length <= 100;
};

util.isJob = function isJob(id) {
  if (typeof id !== "string") return false;

  return id.length >= 12 && id.length <= 21;
};

util.isSID = function isSID(sid) {
  if (typeof sid !== "string") return false;

  return sid.length === 8 && util.isHex(sid);
};

util.isPassword = function isPassword(password) {
  if (typeof password !== "string") return false;

  return password.length > 0 && password.length <= 255;
};

util.isAgent = function isAgent(agent) {
  if (typeof agent !== "string") return false;

  return agent.length > 0 && agent.length <= 255;
};

util.isHex = function isHex(str) {
  return (
    typeof str === "string" && str.length % 2 === 0 && /^[0-9a-f]+$/i.test(str)
  );
};

util.hex32 = function hex32(num) {
  assert(num >= 0);

  num = num.toString(16);

  assert(num.length <= 8);

  while (num.length < 8) num = "0" + num;

  return num;
};

util.toDifficulty = function(bits) {
  let shift = (bits >>> 24) & 0xff;
  let diff = 0x0000ffff / (bits & 0x00ffffff);

  while (shift < 29) {
      diff *= 256.0;
      shift++;
    }

  while (shift > 29) {
      diff /= 256.0;
      shift--;
    }

  return diff;
};

util.targetFromDifficulty = function(difficulty) {
  
  let max = new BN(
      '000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
      'hex'
    );

  let target = max.divn(difficulty);
  let cmpct = consensus.toCompact(target);

  return cmpct;

};
