// functions/scanHIBP.js
const functions = require('firebase-functions/v1');
const https = require('https');

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

exports.checkBreaches = functions.https.onCall(async (data, context) => {
  if (!context.auth) throw new functions.https.HttpsError('unauthenticated', 'Login required.');

  const { email } = data;
  if (!email || !email.includes('@')) {
    throw new functions.https.HttpsError('invalid-argument', 'A valid email address is required.');
  }

  const apiKey = functions.config().hibp?.key;
  if (!apiKey) throw new functions.https.HttpsError('internal', 'HIBP API key not configured.');

  const encoded = encodeURIComponent(email.trim().toLowerCase());

  const [breachRes, pasteRes] = await Promise.all([
    hibpGet(`/breachedaccount/${encoded}?truncateResponse=false`, apiKey),
    hibpGet(`/pasteaccount/${encoded}`, apiKey),
  ]);

  const breaches = breachRes.status === 200 ? JSON.parse(breachRes.body) : [];
  const pastes   = pasteRes.status  === 200 ? JSON.parse(pasteRes.body)  : [];

  return {
    success: true,
    email,
    pwned:       breaches.length > 0 || pastes.length > 0,
    breaches,
    pastes,
    breachCount: breaches.length,
    pasteCount:  pastes.length,
  };
});
