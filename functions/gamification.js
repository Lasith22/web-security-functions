// functions/gamification.js
// Shared points + badge logic called by every scan function

const admin = require('firebase-admin');
const db = admin.firestore();

// ── Badge catalogue ───────────────────────────────────────────────────────────
const BADGE_CATALOGUE = [
  {
    id: 'first_scan',
    name: 'First Scan',
    emoji: '🔍',
    description: 'Completed your first security scan',
    check: (s) => s.totalScans >= 1,
  },
  {
    id: 'scan_veteran',
    name: 'Scan Veteran',
    emoji: '⭐',
    description: 'Completed 10 scans',
    check: (s) => s.totalScans >= 10,
  },
  {
    id: 'security_master',
    name: 'Security Master',
    emoji: '🏆',
    description: 'Completed 50 scans',
    check: (s) => s.totalScans >= 50,
  },
  {
    id: 'bug_hunter',
    name: 'Bug Hunter',
    emoji: '🐛',
    description: 'Discovered a critical vulnerability',
    check: (s) => s.foundCritical,
  },
  {
    id: 'header_champion',
    name: 'Header Champion',
    emoji: '🛡️',
    description: 'Perfect 100% score on an HTTP headers scan',
    check: (s) => s.perfectHttpHeaders,
  },
  {
    id: 'ssl_expert',
    name: 'SSL Expert',
    emoji: '🔒',
    description: 'Perfect 100% score on an SSL/TLS scan',
    check: (s) => s.perfectSSL,
  },
  {
    id: 'clean_code',
    name: 'Clean Code',
    emoji: '✨',
    description: 'Dependency scan with zero vulnerabilities',
    check: (s) => s.cleanDeps,
  },
  {
    id: 'streak_3',
    name: 'On Fire',
    emoji: '🔥',
    description: 'Scanned 3 days in a row',
    check: (s) => s.streak >= 3,
  },
  {
    id: 'streak_7',
    name: 'Week Warrior',
    emoji: '💎',
    description: 'Scanned 7 days in a row',
    check: (s) => s.streak >= 7,
  },
];

// ── Points calculation ────────────────────────────────────────────────────────
function calcBasePoints(summary) {
  let pts = 10; // every scan earns at least 10
  if (summary.securityScore === 100)      pts += 30;
  else if (summary.securityScore >= 80)   pts += 15;
  else if (summary.securityScore >= 60)   pts +=  5;
  // Bonus for finding serious issues (encourages scanning more)
  if (summary.overallSeverity === 'Critical') pts += 20;
  else if (summary.overallSeverity === 'High') pts += 10;
  return pts;
}

// ── Date helpers ──────────────────────────────────────────────────────────────
function todayStr()     { return new Date().toISOString().split('T')[0]; }
function yesterdayStr() {
  const d = new Date(); d.setDate(d.getDate() - 1);
  return d.toISOString().split('T')[0];
}

// ── Main export ───────────────────────────────────────────────────────────────
async function awardPointsAndBadges(userEmail, scanType, summary, findings) {
  const userRef = db.doc(`users/${userEmail}`);
  const snap = await userRef.get();
  const u = snap.exists ? snap.data() : {};

  const today     = todayStr();
  const yesterday = yesterdayStr();

  // ── Streak ────────────────────────────────────────────────────────────────
  const lastDay = u.lastScanDay || null;
  let newStreak;
  if (lastDay === today)      newStreak = u.scanStreak || 1;      // already scanned today
  else if (lastDay === yesterday) newStreak = (u.scanStreak || 0) + 1; // consecutive
  else                        newStreak = 1;                       // reset

  // ── Points ────────────────────────────────────────────────────────────────
  const basePoints  = calcBasePoints(summary);
  const totalScans  = (u.scansCount || 0) + 1;

  // ── Badge conditions ──────────────────────────────────────────────────────
  const hasCritical = (findings || []).some(
    (f) => f.severity === 'Critical' && (f.status === 'Fail' || f.present === false)
  );

  const conditions = {
    totalScans,
    foundCritical:    hasCritical,
    perfectHttpHeaders: scanType === 'HTTP_HEADERS' && summary.securityScore === 100,
    perfectSSL:       scanType === 'SSL_TLS'  && summary.securityScore === 100,
    cleanDeps:        scanType === 'DEPENDENCY' && summary.vulnerabilitiesFound === 0 && totalScans > 0,
    streak:           newStreak,
  };

  const earnedIds   = new Set((u.badges || []).map((b) => b.id));
  // serverTimestamp() cannot be used inside array elements — use ISO string instead
  const nowISO = new Date().toISOString();
  const newBadges   = BADGE_CATALOGUE
    .filter((b) => !earnedIds.has(b.id) && b.check(conditions))
    .map((b) => ({
      id: b.id, name: b.name, emoji: b.emoji, description: b.description,
      earnedAt: nowISO,
    }));

  const badgeBonus   = newBadges.length * 50;
  const pointsEarned = basePoints + badgeBonus;
  const totalPoints  = (u.points || 0) + pointsEarned;

  // ── Write ─────────────────────────────────────────────────────────────────
  await userRef.set({
    points:       totalPoints,
    scansCount:   totalScans,
    badges:       [...(u.badges || []), ...newBadges],
    scanStreak:   newStreak,
    lastScanDay:  today,
    lastScanDate: admin.firestore.FieldValue.serverTimestamp(),
  }, { merge: true });

  return {
    pointsEarned,
    newBadges: newBadges.map(({ id, name, emoji, description }) => ({ id, name, emoji, description })),
    totalPoints,
    currentStreak: newStreak,
  };
}

module.exports = { awardPointsAndBadges, BADGE_CATALOGUE };
