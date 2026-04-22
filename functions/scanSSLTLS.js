// functions/scanSSLTLS.js
const functions = require('firebase-functions/v1');
const admin = require('firebase-admin');
const tls = require('tls');

const db = admin.firestore();

// TLS versions considered insecure
const INSECURE_PROTOCOLS = ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1'];

// Cipher name fragments that indicate weakness
const WEAK_CIPHER_PATTERNS = ['RC4', 'DES', 'NULL', 'EXPORT', 'ANON', 'MD5'];

function extractHostname(rawUrl) {
  if (!rawUrl.startsWith('http')) rawUrl = 'https://' + rawUrl;
  return new URL(rawUrl).hostname;
}

// Connect with rejectUnauthorized:false so we can inspect even broken certs
function tlsHandshake(hostname) {
  return new Promise((resolve, reject) => {
    const socket = tls.connect(
      { host: hostname, port: 443, servername: hostname, rejectUnauthorized: false },
      () => {
        const data = {
          cert: socket.getPeerCertificate(true),
          protocol: socket.getProtocol(),
          cipher: socket.getCipher(),
          authorized: socket.authorized,
          authorizationError: socket.authorizationError || null,
        };
        socket.destroy();
        resolve(data);
      }
    );
    socket.setTimeout(12000, () => { socket.destroy(); reject(new Error('TLS connection timed out')); });
    socket.on('error', reject);
  });
}

function buildFindings({ cert, protocol, cipher, authorized, authorizationError }) {
  const findings = [];

  // ── 1. Certificate Expiry ─────────────────────────────────────────────────
  const validTo = new Date(cert.valid_to);
  const now = new Date();
  const daysLeft = Math.floor((validTo - now) / 86400000);

  if (daysLeft < 0) {
    findings.push({
      check: 'Certificate Expiry',
      status: 'Fail',
      severity: 'Critical',
      value: `Expired ${Math.abs(daysLeft)} days ago (${cert.valid_to})`,
      description: 'The SSL/TLS certificate has expired. Browsers will block access and show security warnings.',
      remediation: 'Renew the certificate immediately through your CA or use a free service like Let\'s Encrypt.',
    });
  } else if (daysLeft < 30) {
    findings.push({
      check: 'Certificate Expiry',
      status: 'Warning',
      severity: 'High',
      value: `Expires in ${daysLeft} days (${cert.valid_to})`,
      description: 'The certificate is expiring very soon. Users will see warnings in under a month.',
      remediation: 'Renew the certificate now to avoid service disruption.',
    });
  } else if (daysLeft < 90) {
    findings.push({
      check: 'Certificate Expiry',
      status: 'Warning',
      severity: 'Medium',
      value: `Expires in ${daysLeft} days (${cert.valid_to})`,
      description: 'The certificate expires within 90 days. Plan renewal soon.',
      remediation: 'Schedule certificate renewal within the next few weeks.',
    });
  } else {
    findings.push({
      check: 'Certificate Expiry',
      status: 'Pass',
      severity: 'Low',
      value: `Valid for ${daysLeft} more days (expires ${cert.valid_to})`,
      description: 'Certificate expiry is within acceptable range.',
      remediation: 'No action needed. Monitor periodically.',
    });
  }

  // ── 2. Certificate Trust / Chain Validity ────────────────────────────────
  const isSelfSigned =
    authorizationError === 'DEPTH_ZERO_SELF_SIGNED_CERT' ||
    authorizationError === 'SELF_SIGNED_CERT_IN_CHAIN';

  if (!authorized) {
    if (isSelfSigned) {
      findings.push({
        check: 'Certificate Trust',
        status: 'Fail',
        severity: 'High',
        value: 'Self-signed certificate',
        description: 'The certificate is self-signed and not trusted by any public CA. Browsers will display a security warning.',
        remediation: 'Replace with a certificate from a trusted CA. Let\'s Encrypt provides free trusted certificates.',
      });
    } else {
      findings.push({
        check: 'Certificate Trust',
        status: 'Fail',
        severity: 'Critical',
        value: authorizationError || 'Untrusted certificate',
        description: 'The certificate chain could not be validated. This may indicate a misconfiguration or MITM attack.',
        remediation: `Verify certificate chain installation. Error: ${authorizationError}`,
      });
    }
  } else {
    findings.push({
      check: 'Certificate Trust',
      status: 'Pass',
      severity: 'Low',
      value: `Trusted — issued by ${cert.issuer?.O || cert.issuer?.CN || 'Unknown CA'}`,
      description: 'The certificate is trusted by a public Certificate Authority.',
      remediation: 'No action needed.',
    });
  }

  // ── 3. TLS Protocol Version ───────────────────────────────────────────────
  if (!protocol) {
    findings.push({
      check: 'TLS Protocol Version',
      status: 'Warning',
      severity: 'Medium',
      value: 'Could not detect protocol version',
      description: 'The TLS protocol version could not be determined.',
      remediation: 'Ensure the server is configured to advertise its TLS version.',
    });
  } else if (protocol === 'TLSv1.3') {
    findings.push({
      check: 'TLS Protocol Version',
      status: 'Pass',
      severity: 'Low',
      value: protocol,
      description: 'TLS 1.3 is the latest and most secure version.',
      remediation: 'No action needed.',
    });
  } else if (protocol === 'TLSv1.2') {
    findings.push({
      check: 'TLS Protocol Version',
      status: 'Pass',
      severity: 'Low',
      value: protocol,
      description: 'TLS 1.2 is acceptable but consider upgrading to TLS 1.3 for best security.',
      remediation: 'Consider enabling TLS 1.3 on your server for improved performance and security.',
    });
  } else if (INSECURE_PROTOCOLS.includes(protocol)) {
    findings.push({
      check: 'TLS Protocol Version',
      status: 'Fail',
      severity: protocol === 'TLSv1.1' ? 'High' : 'Critical',
      value: `${protocol} (deprecated)`,
      description: `${protocol} is deprecated and has known vulnerabilities. RFC 8996 (2021) prohibits TLS 1.0 and 1.1.`,
      remediation: 'Disable TLS 1.0/1.1 on your web server and configure TLS 1.2 as the minimum.',
    });
  }

  // ── 4. Cipher Suite Strength ──────────────────────────────────────────────
  const cipherName = cipher?.name || cipher?.standardName || '';
  const isWeakCipher = WEAK_CIPHER_PATTERNS.some((p) => cipherName.toUpperCase().includes(p));
  // TLS 1.3 mandates ephemeral key exchange — forward secrecy is always present.
  // TLS 1.2 and below encode the key exchange in the cipher name (ECDHE_*, DHE_*).
  const isTLS13 = protocol === 'TLSv1.3';
  const hasForwardSecrecy = isTLS13 || cipherName.toUpperCase().startsWith('ECDHE') || cipherName.toUpperCase().startsWith('DHE');

  if (!cipherName) {
    findings.push({
      check: 'Cipher Suite',
      status: 'Warning',
      severity: 'Medium',
      value: 'Unknown',
      description: 'Could not determine the cipher suite in use.',
      remediation: 'Review your server cipher configuration manually.',
    });
  } else if (isWeakCipher) {
    findings.push({
      check: 'Cipher Suite',
      status: 'Fail',
      severity: 'Critical',
      value: cipherName,
      description: 'The negotiated cipher suite uses a known-weak algorithm (RC4, DES, NULL, EXPORT, ANON, or MD5).',
      remediation: 'Disable weak ciphers. Configure your server to prefer ECDHE/DHE cipher suites only.',
    });
  } else if (!hasForwardSecrecy) {
    findings.push({
      check: 'Cipher Suite',
      status: 'Warning',
      severity: 'Medium',
      value: `${cipherName} (no forward secrecy)`,
      description: 'The cipher suite does not provide Perfect Forward Secrecy. Past sessions could be decrypted if the private key is ever compromised.',
      remediation: 'Configure ECDHE or DHE cipher suites to enable Perfect Forward Secrecy.',
    });
  } else {
    findings.push({
      check: 'Cipher Suite',
      status: 'Pass',
      severity: 'Low',
      value: cipherName,
      description: 'The cipher suite is strong and supports Perfect Forward Secrecy.',
      remediation: 'No action needed.',
    });
  }

  // ── 5. Certificate Key Size ───────────────────────────────────────────────
  const bits = cert.bits;
  if (bits !== undefined) {
    // cert.asn1Curve is set for EC keys; cert.exponent is set for RSA keys.
    // ECDSA P-256 (256-bit) ≈ RSA 3072-bit in strength — perfectly secure.
    // The 2048-bit minimum threshold only applies to RSA.
    const isECKey = !!cert.asn1Curve || (!cert.exponent && bits <= 521);
    const keyLabel = isECKey ? `${bits}-bit ECDSA (${cert.asn1Curve || 'EC'})` : `${bits}-bit RSA`;
    const isWeak = isECKey ? bits < 256 : bits < 2048;

    if (isWeak) {
      findings.push({
        check: 'Key Size',
        status: 'Fail',
        severity: 'High',
        value: keyLabel,
        description: isECKey
          ? `A ${bits}-bit EC key is below the minimum recommended size.`
          : `A ${bits}-bit RSA key is too weak. Minimum recommended is 2048-bit.`,
        remediation: 'Reissue the certificate with at least a 2048-bit RSA key or an ECDSA P-256 key.',
      });
    } else {
      findings.push({
        check: 'Key Size',
        status: 'Pass',
        severity: 'Low',
        value: keyLabel,
        description: isECKey
          ? `ECDSA ${bits}-bit key is strong (equivalent to ~${bits >= 384 ? '7680' : '3072'}-bit RSA).`
          : `${bits}-bit RSA key meets security requirements.`,
        remediation: 'No action needed.',
      });
    }
  }

  return findings;
}

function calcScore(findings) {
  if (findings.length === 0) return 0;
  const passed = findings.filter((f) => f.status === 'Pass').length;
  return Math.round((passed / findings.length) * 100);
}

function calcSeverity(findings) {
  const failed = findings.filter((f) => f.status === 'Fail');
  if (failed.some((f) => f.severity === 'Critical')) return 'Critical';
  if (failed.some((f) => f.severity === 'High')) return 'High';
  if (failed.some((f) => f.severity === 'Medium')) return 'Medium';
  if (findings.some((f) => f.status === 'Warning')) return 'Low';
  return 'Low';
}

// ── Cloud Functions ───────────────────────────────────────────────────────────

exports.scanSSLTLS = functions.https.onCall(async (data, context) => {
  const { url } = data;
  const userEmail = context.auth.token.email;
  const userId = context.auth.uid;

  if (!url || typeof url !== 'string') {
    throw new functions.https.HttpsError('invalid-argument', 'URL is required.');
  }

  let hostname;
  try {
    hostname = extractHostname(url.trim());
  } catch {
    throw new functions.https.HttpsError('invalid-argument', 'Invalid URL format.');
  }

  const targetUrl = `https://${hostname}`;
  functions.logger.info(`SSL/TLS scan requested by ${userEmail} for ${hostname}`);

  try {
    const tlsData = await tlsHandshake(hostname);
    const findings = buildFindings(tlsData);
    const securityScore = calcScore(findings);
    const overallSeverity = calcSeverity(findings);
    const cert = tlsData.cert;

    // ── Firestore document — schema designed for ALL future scan types ────
    // All scan types share: userId, userEmail, scanType, targetUrl/targetEmail/targetFile,
    // timestamp, status, findings[], summary.securityScore, summary.overallSeverity,
    // summary.vulnerabilitiesFound, summary.totalChecks, summary.passedChecks.
    // Type-specific fields live inside summary under their own namespace.
    const scanResult = {
      // ── Universal fields (every scan type has these) ──
      userId,
      userEmail,
      scanType: 'SSL_TLS',
      targetUrl,
      timestamp: admin.firestore.FieldValue.serverTimestamp(),
      status: 'completed',

      findings,

      summary: {
        // Universal sub-fields — safe to read in generic history list
        securityScore,
        overallSeverity,
        totalChecks: findings.length,
        passedChecks: findings.filter((f) => f.status === 'Pass').length,
        vulnerabilitiesFound: findings.filter((f) => f.status === 'Fail').length,
        warningsFound: findings.filter((f) => f.status === 'Warning').length,

        // SSL/TLS-specific sub-fields
        ssl: {
          protocol: tlsData.protocol || 'Unknown',
          cipherName: tlsData.cipher?.name || 'Unknown',
          certSubject: cert.subject?.CN || cert.subject?.O || 'Unknown',
          certIssuer: cert.issuer?.O || cert.issuer?.CN || 'Unknown',
          certValidFrom: cert.valid_from || null,
          certValidTo: cert.valid_to || null,
          daysUntilExpiry: Math.floor((new Date(cert.valid_to) - new Date()) / 86400000),
          isAuthorized: tlsData.authorized,
          authorizationError: tlsData.authorizationError,
        },
      },
    };

    const docRef = await db.collection('scans').add(scanResult);

    // Increment user scan count (same as HTTP headers scanner)
    await db.doc(`users/${userEmail}`).update({
      scansCount: admin.firestore.FieldValue.increment(1),
      lastScanDate: admin.firestore.FieldValue.serverTimestamp(),
    });

    return { success: true, scanId: docRef.id, data: scanResult };
  } catch (error) {
    functions.logger.error('SSL/TLS scan error:', error);

    await db.collection('scans').add({
      userId,
      userEmail,
      scanType: 'SSL_TLS',
      targetUrl,
      timestamp: admin.firestore.FieldValue.serverTimestamp(),
      status: 'failed',
      error: error.message,
    });

    throw new functions.https.HttpsError('internal', `SSL/TLS scan failed: ${error.message}`);
  }
});
