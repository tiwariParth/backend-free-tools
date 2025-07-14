// src/services/dmarcService.js
import { Resolver } from 'dns/promises'
import dmarcParse from 'dmarc-parse'
import mailauth from 'mailauth'

// DNS resolver (Google + Cloudflare)
const resolver = new Resolver()
resolver.setServers(['8.8.8.8', '1.1.1.1'])

// DMARC Analysis
export async function analyzeDMARC(domain) {
  try {
    const txtRecords = await resolver.resolveTxt(`_dmarc.${domain}`)
    const flatRecords = txtRecords.map(entry => entry.join(''))
    const dmarcRecord = flatRecords.find(txt => txt.startsWith('v=DMARC1'))

    if (!dmarcRecord) {
      return {
        success: false,
        error: 'DMARC record not found',
        domain,
        checkedRecord: `_dmarc.${domain}`
      }
    }

    // Use mailauth for DMARC analysis
    let dmarcResult = null
    try {
      dmarcResult = await mailauth.dmarc.verify({
        from: `test@${domain}`,
        spfResult: { status: { result: 'pass' } }, // dummy for analysis
        dkimResult: { status: { result: 'pass' } } // dummy for analysis
      })
    } catch (dmarcError) {
      console.log('DMARC verification error (expected for analysis):', dmarcError.message)
    }

    const analysis = enrichDMARC(parseDMARC(dmarcRecord), dmarcResult)

    return {
      success: true,
      domain,
      checkedRecord: `_dmarc.${domain}`,
      rawRecord: dmarcRecord,
      dmarcResult: dmarcResult,
      ...analysis
    }
  } catch (error) {
    return {
      success: false,
      error: error.message,
      domain
    }
  }
}

// Helper Functions

function parseDMARC(record) {
  let parsed = {}
  
  try {
    // First try with dmarc-parse library
    parsed = dmarcParse(record)
    
    // If the result is empty or invalid, use custom parser
    if (!parsed || Object.keys(parsed).length === 0 || !parsed.v) {
      console.log('dmarc-parse failed, using custom parser')
      parsed = customDMARCParse(record)
    }
  } catch (err) {
    console.log('dmarc-parse error, using custom parser:', err.message)
    parsed = customDMARCParse(record)
  }
  
  // Validate that we have a valid DMARC record
  if (!parsed.v || !parsed.v.includes('DMARC1')) {
    throw new Error('Invalid DMARC record: missing or incorrect version')
  }
  
  return parsed
}

function customDMARCParse(record) {
  const result = {}
  
  // Remove whitespace and split by semicolons
  const parts = record.replace(/\s+/g, '').split(';').filter(part => part.length > 0)
  
  for (const part of parts) {
    const [key, value] = part.split('=', 2)
    if (key && value) {
      switch (key.toLowerCase()) {
        case 'v':
          result.v = value
          break
        case 'p':
          result.p = value
          break
        case 'sp':
          result.sp = value
          break
        case 'adkim':
          result.adkim = value
          break
        case 'aspf':
          result.aspf = value
          break
        case 'pct':
          result.pct = parseInt(value) || 100
          break
        case 'fo':
          result.fo = value
          break
        case 'rf':
          result.rf = value
          break
        case 'ri':
          result.ri = parseInt(value) || 86400
          break
        case 'rua':
          result.rua = value.split(',').map(addr => addr.trim())
          break
        case 'ruf':
          result.ruf = value.split(',').map(addr => addr.trim())
          break
        default:
          // Handle unknown tags
          result[key] = value
      }
    }
  }
  
  return result
}

function enrichDMARC(result, dmarcResult = null) {
  const score = {
    base: 0,
    details: []
  }

  const warnings = []
  const recommendations = []

  // Policy scoring and analysis
  switch (result.p) {
    case 'reject':
      score.base += 5
      score.details.push('Strong policy: reject (+5 points)')
      break
    case 'quarantine':
      score.base += 3
      score.details.push('Moderate policy: quarantine (+3 points)')
      recommendations.push('Consider upgrading to "p=reject" for maximum security')
      break
    case 'none':
      score.base += 0
      warnings.push('Policy "p=none" offers no protection. Consider "quarantine" or "reject".')
      recommendations.push('Start with "p=quarantine" and monitor reports before moving to "p=reject"')
      break
    default:
      warnings.push(`Unknown or missing policy: ${result.p || 'undefined'}`)
      score.base -= 2
  }

  // Reporting configuration
  if (result.rua?.length) {
    score.base += 1
    score.details.push('Aggregate reports configured (+1 point)')
  } else {
    warnings.push('No rua tag configured – you will not receive aggregate reports.')
    recommendations.push('Add rua=mailto:dmarc-reports@yourdomain.com to receive aggregate reports')
  }

  if (result.ruf?.length) {
    score.base += 1
    score.details.push('Forensic reports configured (+1 point)')
  } else {
    recommendations.push('Consider adding ruf=mailto:dmarc-forensic@yourdomain.com for detailed failure reports')
  }

  // Subdomain policy
  if (result.sp) {
    score.base += 1
    score.details.push('Subdomain policy defined (+1 point)')
    if (result.sp === 'reject') {
      score.base += 0.5
      score.details.push('Strong subdomain policy (+0.5 points)')
    }
  } else {
    recommendations.push('Consider adding sp= to explicitly define subdomain policy')
  }

  // Coverage percentage
  const pct = result.pct || 100
  if (pct < 100) {
    warnings.push(`Only ${pct}% of mail is subject to DMARC policy.`)
    score.base -= (100 - pct) / 50 // Reduce score based on coverage
    if (pct < 50) {
      warnings.push('Very low policy coverage - consider increasing pct value')
    }
  } else {
    score.base += 0.5
    score.details.push('Full policy coverage (+0.5 points)')
  }

  // Alignment modes
  if (result.adkim === 's') {
    score.base += 0.5
    score.details.push('Strict DKIM alignment (+0.5 points)')
  }
  
  if (result.aspf === 's') {
    score.base += 0.5
    score.details.push('Strict SPF alignment (+0.5 points)')
  }

  // Add mailauth analysis if available
  if (dmarcResult) {
    if (dmarcResult.status && dmarcResult.status.result) {
      score.details.push(`Mailauth DMARC check: ${dmarcResult.status.result}`)
    }
    if (dmarcResult.info) {
      score.details.push(`DMARC info: ${dmarcResult.info}`)
    }
  }

  // Generate explanations
  const explanations = {
    v: `DMARC version: ${result.v}`,
    
    p: {
      none: 'No enforcement – just monitor and collect reports',
      quarantine: 'Suspicious emails are sent to spam/junk folder',
      reject: 'Unauthenticated emails are completely blocked'
    }[result.p] || `Unknown policy: ${result.p}`,

    rua: result.rua?.length
      ? `Aggregate reports will be sent to: ${result.rua.join(', ')}`
      : 'No aggregate report address configured',

    ruf: result.ruf?.length
      ? `Forensic reports will be sent to: ${result.ruf.join(', ')}`
      : 'No forensic report address configured',

    adkim: result.adkim
      ? `DKIM alignment: ${result.adkim === 's' ? 'strict' : 'relaxed'}`
      : 'DKIM alignment: relaxed (default)',

    aspf: result.aspf
      ? `SPF alignment: ${result.aspf === 's' ? 'strict' : 'relaxed'}`
      : 'SPF alignment: relaxed (default)',

    sp: result.sp
      ? `Subdomain policy: ${result.sp}`
      : 'Subdomain policy: inherits from main policy',

    pct: `${pct}% of emails are subject to this DMARC policy`,

    fo: result.fo
      ? `Failure reporting options: ${result.fo}`
      : 'Failure reporting: default (any failure)',

    ri: result.ri
      ? `Report interval: ${result.ri} seconds (${Math.round(result.ri / 86400)} days)`
      : 'Report interval: 86400 seconds (1 day, default)'
  }

  // Security level assessment
  const finalScore = Math.max(Math.min(score.base, 10), 0)
  let securityLevel = 'Poor'
  if (finalScore >= 8) securityLevel = 'Excellent'
  else if (finalScore >= 6) securityLevel = 'Good'
  else if (finalScore >= 4) securityLevel = 'Fair'

  return {
    parsed: result,
    explanations,
    warnings,
    recommendations,
    score: {
      value: Math.round(finalScore * 10) / 10,
      outOf: 10,
      level: securityLevel,
      details: score.details
    }
  }
}
