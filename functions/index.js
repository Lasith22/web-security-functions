const admin = require('firebase-admin');

admin.initializeApp();

const {
  scanHttpHeaders,
  getScanHistory,
  getScanDetails,
} = require('./scanHttpHeaders');

const { scanSSLTLS } = require('./scanSSLTLS');
const { scanDependencies } = require('./scanDependencies');
const { checkBreaches } = require('./scanHIBP');
const { BADGE_CATALOGUE } = require('./gamification');
const functions = require('firebase-functions/v1');

exports.scanHttpHeaders = scanHttpHeaders;
exports.getScanHistory = getScanHistory;
exports.getScanDetails = getScanDetails;
exports.scanSSLTLS = scanSSLTLS;
exports.scanDependencies = scanDependencies;
exports.checkBreaches = checkBreaches;

// Deletes a scan — only the owner can delete their own scan
exports.deleteScan = functions.https.onCall(async (data, context) => {
  if (!context.auth) throw new functions.https.HttpsError('unauthenticated', 'Login required.');
  const db = admin.firestore();
  const { scanId } = data;
  if (!scanId) throw new functions.https.HttpsError('invalid-argument', 'scanId required.');

  const userEmail = context.auth.token.email;
  const ref = db.collection('scans').doc(scanId);
  const snap = await ref.get();

  if (!snap.exists) throw new functions.https.HttpsError('not-found', 'Scan not found.');
  if (snap.data().userEmail !== userEmail) throw new functions.https.HttpsError('permission-denied', 'Not your scan.');

  await ref.delete();
  await db.doc(`users/${userEmail}`).set(
    { scansCount: admin.firestore.FieldValue.increment(-1) },
    { merge: true }
  );
  return { success: true };
});

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
