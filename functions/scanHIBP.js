// functions/scanHIBP.js
const functions = require('firebase-functions/v1');
const admin = require('firebase-admin');
const https = require('https');
const { awardPointsAndBadges } = require('./gamification');

const db = admin.firestore();

function hibpGet(path, apiKey) {
  return new Promise((resolve, reject) => {
    const options = {
      hostname: 'haveibeenpwned.com',
      path: `/api/v3${path}`,
      headers: {
        'hibp-api-key': apiKey,
        'user-agent': 'WebSecurityScanner',
      },
    };
    const req = https.get(options, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => resolve({ status: res.statusCode, body: data }));
    });
    req.on('error', reject);
  });
}

function calcScore(breachCount) {
  if (breachCount === 0) return 100;
  if (breachCount <= 2)  return 60;
  if (breachCount <= 5)  return 35;
  return 10;
}

function calcSeverity(breachCount) {
  if (breachCount === 0) return 'None';
  if (breachCount <= 2)  return 'Medium';
  if (breachCount <= 5)  return 'High';
  return 'Critical';
}

exports.checkBreaches = functions.https.onCall(async (data, context) => {
  if (!context.auth) throw new functions.https.HttpsError('unauthenticated', 'Login required.');

  const { email } = data;
  if (!email || !email.includes('@')) {
    throw new functions.https.HttpsError('invalid-argument', 'A valid email address is required.');
  }

  const apiKey = functions.config().hibp?.key || '00000000000000000000000000000000';
  const userEmail = context.auth.token.email;
  const encoded = encodeURIComponent(email.trim().toLowerCase());

  const [breachRes, pasteRes] = await Promise.all([
    hibpGet(`/breachedaccount/${encoded}?truncateResponse=false`, apiKey),
    hibpGet(`/pasteaccount/${encoded}`, apiKey),
  ]);

  const breaches = breachRes.status === 200 ? JSON.parse(breachRes.body) : [];
  const pastes   = pasteRes.status  === 200 ? JSON.parse(pasteRes.body)  : [];

  const securityScore       = calcScore(breaches.length);
  const overallSeverity     = calcSeverity(breaches.length);
  const vulnerabilitiesFound = breaches.length + pastes.length;

  const summary = {
    securityScore,
    overallSeverity,
    vulnerabilitiesFound,
    totalChecks:  1,
    passedChecks: breaches.length === 0 ? 1 : 0,
    breach: {
      breachCount: breaches.length,
      pasteCount:  pastes.length,
      pwned:       breaches.length > 0 || pastes.length > 0,
    },
  };

  // Build findings array (one entry per breach)
  const findings = breaches.map((b) => ({
    name:     b.Name,
    title:    b.Title,
    domain:   b.Domain || '',
    date:     b.BreachDate,
    count:    b.PwnCount,
    classes:  b.DataClasses || [],
    severity: breaches.length >= 6 ? 'Critical' : breaches.length >= 3 ? 'High' : 'Medium',
    status:   'Fail',
  }));

  // Save to Firestore
  const scanRef = db.collection('scans').doc();
  await scanRef.set({
    userEmail,
    scanType:  'BREACH_CHECK',
    targetEmail: email.trim().toLowerCase(),
    status:    'completed',
    timestamp: new Date().toISOString(),
    summary,
    findings,
  });

  // Award points & badges
  const gamification = await awardPointsAndBadges(userEmail, 'BREACH_CHECK', summary, findings);

  return {
    success: true,
    scanId:      scanRef.id,
    email,
    pwned:       breaches.length > 0 || pastes.length > 0,
    breaches,
    pastes,
    breachCount: breaches.length,
    pasteCount:  pastes.length,
    gamification,
  };
});
