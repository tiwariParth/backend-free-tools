// src/services/emailAuth.js
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

// SPF Analysis
export async function analyzeSPF(domain) {
  try {
    const txtRecords = await resolver.resolveTxt(domain)
    const flatRecords = txtRecords.map(entry => entry.join(''))
    const spfRecord = flatRecords.find(txt => txt.startsWith('v=spf1'))

    if (!spfRecord) {
      return {
        success: false,
        error: 'SPF record not found',
        domain,
        recommendations: [
          'Add an SPF record to your domain to specify which mail servers are authorized to send emails',
          'Example: "v=spf1 include:_spf.google.com ~all" for Google Workspace'
        ]
      }
    }

    // Use mailauth for comprehensive email authentication
    let mailauthResult = null
    try {
      const testMessage = `From: test@${domain}\r\nTo: test@example.com\r\nSubject: SPF Test\r\n\r\nTest message for SPF analysis`
      mailauthResult = await mailauth.authenticate(testMessage, {
        ip: '8.8.8.8', // Google's IP for testing
        helo: domain,
        sender: `test@${domain}`
      })
    } catch (authError) {
      console.log('Mailauth SPF error (expected for analysis):', authError.message)
    }

    const analysis = analyzeSPFRecord(spfRecord, mailauthResult)

    return {
      success: true,
      domain,
      rawRecord: spfRecord,
      mailauthResult: mailauthResult,
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

// MX Analysis
export async function analyzeMX(domain) {
  try {
    const mxRecords = await resolver.resolveMx(domain)
    
    if (!mxRecords || mxRecords.length === 0) {
      return {
        success: false,
        error: 'No MX records found',
        domain,
        recommendations: [
          'Add MX records to enable email delivery to your domain',
          'MX records specify which mail servers handle email for your domain'
        ]
      }
    }

    // Sort by priority (lower numbers = higher priority)
    const sortedMx = mxRecords.sort((a, b) => a.priority - b.priority)
    
    const analysis = analyzeMXRecords(sortedMx)

    return {
      success: true,
      domain,
      records: sortedMx,
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

// Comprehensive Email Security Check
export async function analyzeEmailSecurity(domain, dkimSelector = 'default') {
  const results = await Promise.allSettled([
    analyzeDMARC(domain),
    analyzeSPF(domain),
    analyzeDKIM(domain, dkimSelector),
    analyzeMX(domain)
  ])

  const [dmarcResult, spfResult, dkimResult, mxResult] = results.map(r => 
    r.status === 'fulfilled' ? r.value : { success: false, error: r.reason.message }
  )

  // Calculate overall security score
  let totalScore = 0
  let maxScore = 0

  if (dmarcResult.success && dmarcResult.score) {
    totalScore += dmarcResult.score.value
    maxScore += dmarcResult.score.outOf
  }
  
  if (spfResult.success && spfResult.score) {
    totalScore += spfResult.score.value
    maxScore += spfResult.score.outOf
  }
  
  if (dkimResult.success && dkimResult.score) {
    totalScore += dkimResult.score.value
    maxScore += dkimResult.score.outOf
  }

  if (mxResult.success && mxResult.score) {
    totalScore += mxResult.score.value
    maxScore += mxResult.score.outOf
  }

  const overallScore = maxScore > 0 ? (totalScore / maxScore) * 10 : 0
  let securityLevel = 'Poor'
  if (overallScore >= 8) securityLevel = 'Excellent'
  else if (overallScore >= 6) securityLevel = 'Good'
  else if (overallScore >= 4) securityLevel = 'Fair'

  return {
    domain,
    dmarc: dmarcResult,
    spf: spfResult,
    dkim: dkimResult,
    mx: mxResult,
    overallScore: {
      value: Math.round(overallScore * 10) / 10,
      outOf: 10,
      level: securityLevel
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

function analyzeSPFRecord(record, spfResult = null) {
  const score = { base: 0, details: [] }
  const warnings = []
  const recommendations = []

  // Basic SPF validation
  if (!record.startsWith('v=spf1')) {
    warnings.push('Invalid SPF record format')
    return { score: { value: 0, outOf: 5, level: 'Poor' }, warnings, recommendations }
  }

  score.base += 1
  score.details.push('Valid SPF record format (+1 point)')

  // Check for mechanisms
  const mechanisms = record.split(' ').filter(part => part !== 'v=spf1')
  
  if (mechanisms.some(m => m.startsWith('include:'))) {
    score.base += 1
    score.details.push('Uses include mechanism (+1 point)')
  }

  if (mechanisms.some(m => m.startsWith('a') || m.startsWith('mx'))) {
    score.base += 1
    score.details.push('Uses a/mx mechanism (+1 point)')
  }

  // Check for proper ending
  const ending = mechanisms[mechanisms.length - 1]
  if (ending === '~all') {
    score.base += 1.5
    score.details.push('Soft fail policy (~all) (+1.5 points)')
  } else if (ending === '-all') {
    score.base += 2
    score.details.push('Hard fail policy (-all) (+2 points)')
  } else if (ending === '?all') {
    score.base += 0.5
    score.details.push('Neutral policy (?all) (+0.5 points)')
    recommendations.push('Consider using ~all or -all for better security')
  } else {
    warnings.push('SPF record should end with an "all" mechanism')
    recommendations.push('Add ~all or -all at the end of your SPF record')
  }

  // Add mailauth analysis if available
  if (spfResult) {
    if (spfResult.status && spfResult.status.result) {
      score.details.push(`Mailauth SPF check: ${spfResult.status.result}`)
    }
  }

  const finalScore = Math.max(Math.min(score.base, 5), 0)
  let securityLevel = 'Poor'
  if (finalScore >= 4) securityLevel = 'Excellent'
  else if (finalScore >= 3) securityLevel = 'Good'
  else if (finalScore >= 2) securityLevel = 'Fair'

  return {
    parsed: mechanisms,
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

function analyzeMXRecords(records) {
  const score = { base: 0, details: [] }
  const warnings = []
  const recommendations = []

  if (records.length === 0) {
    warnings.push('No MX records found')
    return { score: { value: 0, outOf: 3, level: 'Poor' }, warnings, recommendations }
  }

  score.base += 1
  score.details.push('MX records present (+1 point)')

  if (records.length >= 2) {
    score.base += 1
    score.details.push('Multiple MX records for redundancy (+1 point)')
  } else {
    recommendations.push('Consider adding backup MX records for redundancy')
  }

  // Check for proper priority configuration
  const priorities = records.map(r => r.priority)
  const uniquePriorities = [...new Set(priorities)]
  
  if (uniquePriorities.length === records.length) {
    score.base += 1
    score.details.push('Proper priority configuration (+1 point)')
  } else {
    warnings.push('Some MX records have the same priority')
  }

  const finalScore = Math.max(Math.min(score.base, 3), 0)
  let securityLevel = 'Poor'
  if (finalScore >= 2.5) securityLevel = 'Excellent'
  else if (finalScore >= 2) securityLevel = 'Good'
  else if (finalScore >= 1) securityLevel = 'Fair'

  return {
    warnings,
    recommendations,
    score: {
      value: Math.round(finalScore * 10) / 10,
      outOf: 3,
      level: securityLevel,
      details: score.details
    }
  }
}
