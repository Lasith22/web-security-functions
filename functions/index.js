const admin = require('firebase-admin');

admin.initializeApp();

const {
  scanHttpHeaders,
  getScanHistory,
  getScanDetails,
} = require('./scanHttpHeaders');

const { scanSSLTLS } = require('./scanSSLTLS');
const { scanDependencies } = require('./scanDependencies');
const { BADGE_CATALOGUE } = require('./gamification');
const functions = require('firebase-functions/v1');

exports.scanHttpHeaders = scanHttpHeaders;
exports.getScanHistory = getScanHistory;
exports.getScanDetails = getScanDetails;
exports.scanSSLTLS = scanSSLTLS;
exports.scanDependencies = scanDependencies;

// Returns the current user's points, badges and streak
exports.getUserProfile = functions.https.onCall(async (data, context) => {
  const db = admin.firestore();
  const userEmail = context.auth.token.email;
  const snap = await db.doc(`users/${userEmail}`).get();
  const u = snap.exists ? snap.data() : {};

  // earnedAt is stored as an ISO string — pass it through directly
  const earnedBadges = u.badges || [];

  return {
    success: true,
    profile: {
      points:      u.points      || 0,
      scansCount:  u.scansCount  || 0,
      scanStreak:  u.scanStreak  || 0,
      badges:      earnedBadges,
      allBadges:   BADGE_CATALOGUE.map(({ id, name, emoji, description }) => ({ id, name, emoji, description })),
    },
  };
});
