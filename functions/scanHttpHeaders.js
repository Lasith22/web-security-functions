// functions/src/scanHttpHeaders.js
const functions = require('firebase-functions/v1');
const admin = require('firebase-admin');
const fetch = require('node-fetch');
const { awardPointsAndBadges } = require('./gamification');

const db = admin.firestore();

// Common HTTP Security Headers
const SECURITY_HEADERS = {
  'X-Frame-Options': {
    name: 'X-Frame-Options',
    severity: 'High',
    description:
      'Prevents clickjacking attacks by controlling whether your site can be embedded in iframes.',
    remediation: 'Set to "DENY" or "SAMEORIGIN"',
    goodValues: ['DENY', 'SAMEORIGIN'],
  },
  'X-Content-Type-Options': {
    name: 'X-Content-Type-Options',
    severity: 'Medium',
    description: 'Prevents MIME type sniffing attacks.',
    remediation: 'Set to "nosniff"',
    goodValues: ['nosniff'],
  },
  'Content-Security-Policy': {
    name: 'Content-Security-Policy',
    severity: 'High',
    description:
      'Controls which resources can be loaded, preventing XSS attacks.',
    remediation: 'Implement a comprehensive CSP policy',
    goodValues: ['*'], // Any value is good, just needs to exist
  },
  'Strict-Transport-Security': {
    name: 'Strict-Transport-Security',
    severity: 'High',
    description:
      'Forces HTTPS connections to prevent man-in-the-middle attacks.',
    remediation: 'Set to "max-age=31536000; includeSubDomains"',
    goodValues: ['*'],
  },
  'X-XSS-Protection': {
    name: 'X-XSS-Protection',
    severity: 'Medium',
    description: 'Enables XSS protection in older browsers.',
    remediation: 'Set to "1; mode=block"',
    goodValues: ['1; mode=block'],
  },
  'Referrer-Policy': {
    name: 'Referrer-Policy',
    severity: 'Low',
    description: 'Controls how much referrer information is shared.',
    remediation: 'Set to "no-referrer" or "strict-origin-when-cross-origin"',
    goodValues: ['*'],
  },
};

// Helper function to validate URL
function isValidUrl(string) {
  try {
    new URL(string);
    return true;
  } catch (_) {
    return false;
  }
}

// Helper function to normalize URL
function normalizeUrl(url) {
  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    url = 'https://' + url;
  }
  return url;
}

// Main scanning function
exports.scanHttpHeaders = functions.https.onCall(async (data, context) => {
  // Check if user is authenticated
  // if (!context.auth) {
  //   throw new functions.https.HttpsError(
  //     'unauthenticated',
  //     'User must be authenticated to use this function.'
  //   );
  // }

  const { url } = data;

  functions.logger.info(
    `User ${context.auth.token.email} initiated a scan for URL: ${url}`
  );
  const userEmail = context.auth.token.email;

  // Validate input
  if (!url || typeof url !== 'string') {
    throw new functions.https.HttpsError(
      'invalid-argument',
      'URL is required and must be a string.'
    );
  }

  const normalizedUrl = normalizeUrl(url);

  if (!isValidUrl(normalizedUrl)) {
    throw new functions.https.HttpsError(
      'invalid-argument',
      'Invalid URL format.'
    );
  }

  try {
    // Fetch website headers
    const response = await fetch(normalizedUrl, {
      method: 'HEAD',
      timeout: 10000,
      redirect: 'follow',
    });

    const headers = response.headers.raw();

    // Check for missing/present headers
    const findings = [];
    let vulnerabilitiesFound = 0;

    Object.entries(SECURITY_HEADERS).forEach(([headerKey, headerInfo]) => {
      const headerValue = Object.keys(headers).find(
        (key) => key.toLowerCase() === headerKey.toLowerCase()
      );

      if (!headerValue) {
        // Header is missing
        findings.push({
          header: headerInfo.name,
          status: 'Missing',
          severity: headerInfo.severity,
          value: null,
          description: headerInfo.description,
          remediation: headerInfo.remediation,
          present: false,
        });
        vulnerabilitiesFound++;
      } else {
        // Header is present
        const value = headers[headerValue];
        findings.push({
          header: headerInfo.name,
          status: 'Present',
          severity: headerInfo.severity,
          value: Array.isArray(value) ? value.join('; ') : value,
          description: headerInfo.description,
          remediation: headerInfo.remediation,
          present: true,
        });
      }
    });

    // Calculate score
    const presentHeaders = findings.filter((f) => f.present).length;
    const securityScore = Math.round((presentHeaders / findings.length) * 100);

    // Determine overall severity
    let overallSeverity = 'Low';
    const criticalCount = findings.filter(
      (f) => !f.present && f.severity === 'High'
    ).length;
    if (criticalCount >= 3) {
      overallSeverity = 'Critical';
    } else if (criticalCount >= 2) {
      overallSeverity = 'High';
    } else if (criticalCount >= 1) {
      overallSeverity = 'Medium';
    }

    // Create scan result object
    const scanResult = {
      userId: context.auth.uid,
      userEmail: userEmail,
      scanType: 'HTTP_HEADERS',
      targetUrl: normalizedUrl,
      timestamp: admin.firestore.FieldValue.serverTimestamp(),
      findings: findings,
      summary: {
        totalHeaders: findings.length,
        presentHeaders: presentHeaders,
        missingHeaders: findings.length - presentHeaders,
        securityScore: securityScore,
        overallSeverity: overallSeverity,
        vulnerabilitiesFound: vulnerabilitiesFound,
      },
      status: 'completed',
    };

    // Save to Firestore
    const docRef = await db.collection('scans').add(scanResult);

    // Award points and badges
    const gamification = await awardPointsAndBadges(
      userEmail, 'HTTP_HEADERS', scanResult.summary, scanResult.findings
    );

    return {
      success: true,
      scanId: docRef.id,
      data: scanResult,
      gamification,
    };
  } catch (error) {
    console.error('Scan error:', error);

    // Save failed scan attempt
    await db.collection('scans').add({
      userId: context.auth.uid,
      userEmail: userEmail,
      scanType: 'HTTP_HEADERS',
      targetUrl: normalizedUrl,
      timestamp: admin.firestore.FieldValue.serverTimestamp(),
      status: 'failed',
      error: error.message,
    });

    throw new functions.https.HttpsError(
      'internal',
      `Failed to scan website: ${error.message}`
    );
  }
});

// Get user's scan history
exports.getScanHistory = functions.https.onCall(async (data, context) => {
  // if (!context.auth) {
  //   throw new functions.https.HttpsError(
  //     'unauthenticated',
  //     'User must be authenticated.'
  //   );
  // }

  const userEmail = context.auth.token.email;
  const limit = data.limit || 10;

  try {
    const snapshot = await db
      .collection('scans')
      .where('userEmail', '==', userEmail)
      .orderBy('timestamp', 'desc')
      .limit(limit)
      .get();

    const scans = [];
    snapshot.forEach((doc) => {
      scans.push({
        id: doc.id,
        ...doc.data(),
        timestamp: doc.data().timestamp.toDate(),
      });
    });

    return {
      success: true,
      scans: scans,
    };
  } catch (error) {
    console.error('Error fetching scan history:', error);
    throw new functions.https.HttpsError('internal', error.message);
  }
});

// Get specific scan details
exports.getScanDetails = functions.https.onCall(async (data, context) => {
  // if (!context.auth) {
  //   throw new functions.https.HttpsError(
  //     'unauthenticated',
  //     'User must be authenticated.'
  //   );
  // }

  const { scanId } = data;
  const userEmail = context.auth.token.email;

  if (!scanId) {
    throw new functions.https.HttpsError(
      'invalid-argument',
      'scanId is required.'
    );
  }

  try {
    const doc = await db.collection('scans').doc(scanId).get();

    if (!doc.exists) {
      throw new functions.https.HttpsError('not-found', 'Scan not found.');
    }

    const scanData = doc.data();

    // Security check: user can only view their own scans
    if (scanData.userEmail !== userEmail) {
      throw new functions.https.HttpsError(
        'permission-denied',
        'You do not have permission to view this scan.'
      );
    }

    return {
      success: true,
      scan: {
        id: scanId,
        ...scanData,
        timestamp: scanData.timestamp.toDate(),
      },
    };
  } catch (error) {
    console.error('Error fetching scan details:', error);
    throw new functions.https.HttpsError('internal', error.message);
  }
});
