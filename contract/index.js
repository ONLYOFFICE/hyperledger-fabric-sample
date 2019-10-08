'use strict';

const FilePasswordStorage = require('./lib/FilePasswordStorage');
const PublicKeyStorage = require('./lib/PublicKeyStorage');

module.exports.FilePasswordStorage = FilePasswordStorage;
module.exports.PublicKeyStorage = PublicKeyStorage;

module.exports.contracts = [ FilePasswordStorage, PublicKeyStorage ] ;