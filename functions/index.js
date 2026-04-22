const admin = require('firebase-admin');

admin.initializeApp();

const {
  scanHttpHeaders,
  getScanHistory,
  getScanDetails,
} = require('./scanHttpHeaders');

const { scanSSLTLS } = require('./scanSSLTLS');

exports.scanHttpHeaders = scanHttpHeaders;
exports.getScanHistory = getScanHistory;
exports.getScanDetails = getScanDetails;
exports.scanSSLTLS = scanSSLTLS;
