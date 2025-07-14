// src/services/dkimService.js
import { Resolver } from 'dns/promises'
import mailauth from 'mailauth'

// DNS resolver (Google + Cloudflare)
const resolver = new Resolver()
resolver.setServers(['8.8.8.8', '1.1.1.1'])

// DKIM Analysis
export async function analyzeDKIM(domain, selector = 'default') {
  try {
    const dkimRecord = `${selector}._domainkey.${domain}`
    
    try {
      const txtRecords = await resolver.resolveTxt(dkimRecord)
      const flatRecords = txtRecords.map(entry => entry.join(''))
      const dkimKey = flatRecords.find(txt => txt.includes('v=DKIM1') || txt.includes('k=rsa') || txt.includes('p='))

      if (!dkimKey) {
        return {
          success: false,
          error: `DKIM record not found for selector '${selector}'`,
          domain,
          selector,
          checkedRecord: dkimRecord,
          recommendations: [
            'Set up DKIM signing for your domain',
            'Common selectors to try: default, google, mail, dkim',
            'Contact your email provider for DKIM setup instructions'
          ]
        }
      }

      // Use mailauth for comprehensive analysis
      let mailauthResult = null
      try {
        const testMessage = `DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=${domain}; s=${selector}; h=from:to:subject; bh=test; b=test\r\nFrom: test@${domain}\r\nTo: test@example.com\r\nSubject: DKIM Test\r\n\r\nTest message for DKIM analysis`
        mailauthResult = await mailauth.authenticate(testMessage, {
          ip: '8.8.8.8',
          helo: domain,
          sender: `test@${domain}`
        })
      } catch (authError) {
        console.log('Mailauth DKIM error (expected for analysis):', authError.message)
      }

      const analysis = analyzeDKIMRecord(dkimKey, mailauthResult)

      return {
        success: true,
        domain,
        selector,
        checkedRecord: dkimRecord,
        rawRecord: dkimKey,
        mailauthResult: mailauthResult,
        ...analysis
      }
    } catch (dnsError) {
      return {
        success: false,
        error: `DKIM record not found for selector '${selector}'`,
        domain,
        selector,
        checkedRecord: dkimRecord,
        recommendations: [
          'Try common selectors: default, google, mail, dkim, selector1, selector2',
          'Check with your email provider for the correct DKIM selector',
          'Ensure DKIM is properly configured in your DNS'
        ]
      }
    }
  } catch (error) {
    return {
      success: false,
      error: error.message,
      domain,
      selector
    }
  }
}

function analyzeDKIMRecord(record, dkimResult = null) {
  const score = { base: 0, details: [] }
  const warnings = []
  const recommendations = []

  // Basic DKIM validation
  if (!record.includes('v=DKIM1') && !record.includes('k=rsa') && !record.includes('p=')) {
    warnings.push('Invalid DKIM record format')
    return { score: { value: 0, outOf: 5, level: 'Poor' }, warnings, recommendations }
  }

  score.base += 1
  score.details.push('Valid DKIM record found (+1 point)')

  // Check for public key
  if (record.includes('p=') && !record.includes('p=;')) {
    score.base += 2
    score.details.push('Public key present (+2 points)')
  } else {
    warnings.push('No public key found in DKIM record')
  }

  // Check key type
  if (record.includes('k=rsa')) {
    score.base += 1
    score.details.push('RSA key type (+1 point)')
  }

  // Check for hash algorithms
  if (record.includes('h=sha256')) {
    score.base += 1
    score.details.push('SHA-256 hash algorithm (+1 point)')
  } else if (record.includes('h=sha1')) {
    score.base += 0.5
    score.details.push('SHA-1 hash algorithm (+0.5 points)')
    recommendations.push('Consider upgrading to SHA-256 for better security')
  }

  // Add mailauth analysis if available
  if (dkimResult) {
    if (dkimResult.status && dkimResult.status.result) {
      score.details.push(`Mailauth DKIM check: ${dkimResult.status.result}`)
    }
    if (dkimResult.info) {
      score.details.push(`DKIM info: ${dkimResult.info}`)
    }
  }

  const finalScore = Math.max(Math.min(score.base, 5), 0)
  let securityLevel = 'Poor'
  if (finalScore >= 4) securityLevel = 'Excellent'
  else if (finalScore >= 3) securityLevel = 'Good'
  else if (finalScore >= 2) securityLevel = 'Fair'

  return {
    warnings,
    recommendations,
    score: {
      value: Math.round(finalScore * 10) / 10,
      outOf: 5,
      level: securityLevel,
      details: score.details
    }
  }
}
