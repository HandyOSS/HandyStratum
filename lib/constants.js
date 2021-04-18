/*!
 * constants.js - constants for HandyStratum server
 * Copyright (c) 2017-2018, Christopher Jeffrey (MIT License).
 * Copyright (c) 2019, Handshake Alliance (MIT License).
 * Copyright (c) 2021, HandyMiner: Alex Smith, Steven McKie, Thomas Costanzo (MIT License)
 * https://github.com/HandyMiner/HandyStratum
 */

"use strict";

const constants = {};

constants.NONCE_SIZE = 4;
constants.USE_MASK = false;
constants.ACTIVE_TIME = 60;
constants.MAX_JOBS = 6;
constants.SHARES_PER_MINUTE = 8;
constants.BAN_SCORE = 1000;
constants.BAN_TIME = 10 * 60;
constants.INITIAL_DIFFICULTY = 32;

module.exports = constants;
