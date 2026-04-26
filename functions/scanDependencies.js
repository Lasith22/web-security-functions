// functions/scanDependencies.js
const functions = require('firebase-functions/v1');
const admin = require('firebase-admin');
const fetch = require('node-fetch');
const { awardPointsAndBadges } = require('./gamification');

const db = admin.firestore();

const OSV_BATCH_URL = 'https://api.osv.dev/v1/querybatch';
const MAX_PACKAGES = 150; // guard against huge package.json files

// Strip semver range prefixes so OSV can match an exact version
function cleanVersion(raw) {
  if (!raw || typeof raw !== 'string') return null;
  // skip non-version strings (URLs, git refs, 'latest', '*', 'workspace:*')
  if (raw === '*' || raw === 'latest' || raw.startsWith('http') || raw.startsWith('git')) return null;
  const cleaned = raw.replace(/^[\^~>=<]+/, '').trim().split(/\s+/)[0].split('||')[0].trim();
  // must look like a semver: starts with a digit
  return /^\d/.test(cleaned) ? cleaned : null;
}

// Extract a human-readable severity from OSV vulnerability object
function extractSeverity(vuln) {
  // GitHub Advisory Database includes plain-english severity
  const dbSev = vuln.database_specific?.severity;
  if (dbSev) {
    const s = dbSev.toUpperCase();
    if (s === 'CRITICAL') return 'Critical';
    if (s === 'HIGH') return 'High';
    if (s === 'MODERATE' || s === 'MEDIUM') return 'Medium';
    if (s === 'LOW') return 'Low';
  }

  // Fall back to CVSS vector heuristic (look at impact metrics C/I/A)
  const cvss = vuln.severity?.[0]?.score || '';
  if (cvss) {
    const highImpact = ['/C:H', '/I:H', '/A:H'].filter((m) => cvss.includes(m)).length;
    if (highImpact >= 2) return 'Critical';
    if (highImpact >= 1) return 'High';
    const lowImpact = cvss.includes('/C:L') && cvss.includes('/I:L') && cvss.includes('/A:L');
    if (lowImpact) return 'Low';
  }

  return 'Medium';
}

// Highest severity across all vulns for a package
function worstSeverity(vulns) {
  const order = ['Critical', 'High', 'Medium', 'Low'];
  for (const level of order) {
    if (vulns.some((v) => extractSeverity(v) === level)) return level;
  }
  return 'Medium';
}

exports.scanDependencies = functions
  .runWith({ timeoutSeconds: 120 }) // OSV batch can take a moment
  .https.onCall(async (data, context) => {
    const userEmail = context.auth.token.email;
    const userId = context.auth.uid;

    const { packageJsonContent, fileName } = data;

    if (!packageJsonContent || typeof packageJsonContent !== 'string') {
      throw new functions.https.HttpsError('invalid-argument', 'package.json content is required.');
    }

    // ── Parse package.json ────────────────────────────────────────────────
    let parsed;
    try {
      parsed = JSON.parse(packageJsonContent);
    } catch {
      throw new functions.https.HttpsError('invalid-argument', 'Invalid JSON — could not parse package.json.');
    }

    const allDeps = {
      ...( parsed.dependencies || {}),
      ...(parsed.devDependencies || {}),
    };

    const packageNames = Object.keys(allDeps);
    if (packageNames.length === 0) {
      throw new functions.https.HttpsError('invalid-argument', 'No dependencies found in package.json.');
    }

    // Build list of queryable packages (those with a resolvable version)
    const queryable = packageNames
      .slice(0, MAX_PACKAGES)
      .map((name) => {
        const rawVersion = allDeps[name];
        const version = cleanVersion(rawVersion);
        return { name, rawVersion, version };
      });

    const withVersion = queryable.filter((p) => p.version !== null);
    const skipped = queryable.filter((p) => p.version === null);

    functions.logger.info(
      `Dependency scan by ${userEmail}: ${withVersion.length} queryable packages, ${skipped.length} skipped`
    );

    // ── OSV Batch Query ───────────────────────────────────────────────────
    const osvQueries = withVersion.map((pkg) => ({
      version: pkg.version,
      package: { name: pkg.name, ecosystem: 'npm' },
    }));

    let osvResponse;
    try {
      const res = await fetch(OSV_BATCH_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ queries: osvQueries }),
        timeout: 60000,
      });
      osvResponse = await res.json();
    } catch (err) {
      throw new functions.https.HttpsError('internal', `OSV API request failed: ${err.message}`);
    }

    const results = osvResponse.results || [];

    // ── Build findings ─────────────────────────────────────────────────
    const findings = [];

    withVersion.forEach((pkg, idx) => {
      const vulns = results[idx]?.vulns || [];

      if (vulns.length === 0) {
        findings.push({
          package: pkg.name,
          version: pkg.version,
          rawVersion: pkg.rawVersion,
          status: 'Pass',
          severity: 'Low',
          vulnerabilityCount: 0,
          vulnerabilities: [],
          description: `No known vulnerabilities found for ${pkg.name}@${pkg.version}.`,
          remediation: 'No action needed.',
        });
      } else {
        const severity = worstSeverity(vulns);
        const vulnDetails = vulns.slice(0, 5).map((v) => ({
          id: v.id,
          summary: v.summary || 'No summary available',
          severity: extractSeverity(v),
          published: v.published ? v.published.split('T')[0] : 'Unknown',
          references: (v.references || []).slice(0, 2).map((r) => r.url),
        }));

        findings.push({
          package: pkg.name,
          version: pkg.version,
          rawVersion: pkg.rawVersion,
          status: 'Fail',
          severity,
          vulnerabilityCount: vulns.length,
          vulnerabilities: vulnDetails,
          description: `${vulns.length} known vulnerabilit${vulns.length === 1 ? 'y' : 'ies'} found in ${pkg.name}@${pkg.version}.`,
          remediation: `Update ${pkg.name} to the latest version. Run: npm update ${pkg.name}`,
        });
      }
    });

    // Sort: vulnerable packages first, then by severity
    const sevOrder = { Critical: 0, High: 1, Medium: 2, Low: 3 };
    findings.sort((a, b) => {
      if (a.status !== b.status) return a.status === 'Fail' ? -1 : 1;
      return (sevOrder[a.severity] ?? 4) - (sevOrder[b.severity] ?? 4);
    });

    // ── Summary ────────────────────────────────────────────────────────
    const vulnerableCount = findings.filter((f) => f.status === 'Fail').length;
    const passedCount = findings.filter((f) => f.status === 'Pass').length;
    const securityScore = findings.length > 0
      ? Math.round((passedCount / findings.length) * 100)
      : 100;

    const criticalCount = findings.filter((f) => f.status === 'Fail' && f.severity === 'Critical').length;
    const highCount     = findings.filter((f) => f.status === 'Fail' && f.severity === 'High').length;
    const mediumCount   = findings.filter((f) => f.status === 'Fail' && f.severity === 'Medium').length;

    let overallSeverity = 'Low';
    if (criticalCount > 0) overallSeverity = 'Critical';
    else if (highCount > 0) overallSeverity = 'High';
    else if (mediumCount > 0) overallSeverity = 'Medium';

    const totalVulnCount = findings.reduce((sum, f) => sum + f.vulnerabilityCount, 0);

    // ── Firestore — same universal schema as other scan types ──────────
    const scanResult = {
      userId,
      userEmail,
      scanType: 'DEPENDENCY',
      targetFile: fileName || 'package.json',
      timestamp: admin.firestore.FieldValue.serverTimestamp(),
      status: 'completed',

      findings,

      summary: {
        // Universal fields
        securityScore,
        overallSeverity,
        totalChecks: findings.length,
        passedChecks: passedCount,
        vulnerabilitiesFound: vulnerableCount,
        warningsFound: 0,

        // Dependency-specific fields
        dependency: {
          totalPackages: packageNames.length,
          scannedPackages: findings.length,
          skippedPackages: skipped.length + Math.max(0, packageNames.length - MAX_PACKAGES),
          vulnerablePackages: vulnerableCount,
          cleanPackages: passedCount,
          totalCVEs: totalVulnCount,
          criticalCount,
          highCount,
          mediumCount,
        },
      },
    };

    const docRef = await db.collection('scans').add(scanResult);

    const gamification = await awardPointsAndBadges(
      userEmail, 'DEPENDENCY', scanResult.summary, scanResult.findings
    );

    return { success: true, scanId: docRef.id, data: scanResult, gamification };
  });
