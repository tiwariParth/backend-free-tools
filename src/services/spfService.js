// src/services/spfService.js
import { Resolver } from 'dns/promises'
import mailauth from 'mailauth'

// DNS resolver (Google + Cloudflare)
const resolver = new Resolver()
resolver.setServers(['8.8.8.8', '1.1.1.1'])

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
