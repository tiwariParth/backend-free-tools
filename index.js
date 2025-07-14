// index.js
import express from 'express'
import dmarcParsePackage from 'dmarc-parse'
import { Resolver } from 'dns/promises'
import expressAsyncApi from 'express-async-api'
import crypto from 'crypto'

const { parse: dmarcParse } = dmarcParsePackage

const app = express()
const PORT = 3000

app.use(express.json())

// Use express-async-api for better error handling
expressAsyncApi(app)

// CORS middleware (enhanced for frontend integration)
app.use((_, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*')
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization')
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
  next()
})

// DNS resolver (Google + Cloudflare)
const resolver = new Resolver()
resolver.setServers(['8.8.8.8', '1.1.1.1'])

// In-memory captcha store (in production, use Redis or database)
const captchaStore = new Map()

// Generate captcha SVG
function generateCaptchaSVG(text) {
  const colors = ['#FF6B6B', '#4ECDC4', '#45B7D1', '#96CEB4', '#FFEAA7', '#DDA0DD', '#98D8C8']
  const randomColor = colors[Math.floor(Math.random() * colors.length)]
  
  return `<svg width="120" height="40" xmlns="http://www.w3.org/2000/svg">
    <rect width="120" height="40" fill="#f8f9fa" stroke="#dee2e6" stroke-width="1"/>
    <text x="60" y="25" font-family="Arial, sans-serif" font-size="18" font-weight="bold" 
          text-anchor="middle" fill="${randomColor}" 
          transform="rotate(${Math.random() * 10 - 5} 60 20)">${text}</text>
    ${Array.from({length: 20}, () => 
      `<circle cx="${Math.random() * 120}" cy="${Math.random() * 40}" r="1" fill="${randomColor}" opacity="0.3"/>`
    ).join('')}
  </svg>`
}

// Generate random captcha text
function generateCaptchaText() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
  let result = ''
  for (let i = 0; i < 5; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length))
  }
  return result
}

// Rate limiting store (in production, use Redis)
const rateLimitStore = new Map()

// Custom DMARC parser as fallback
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

// Robust DMARC analyzer function
function analyzeDMARC(record) {
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
  
  return enrichDMARC(parsed)
}
// Util: Add contextual explanations and scoring
function enrichDMARC(result) {
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
    },
    summary: {
      hasPolicy: !!result.p && result.p !== 'none',
      hasReporting: !!(result.rua?.length || result.ruf?.length),
      isSecure: finalScore >= 6,
      coverage: pct
    }
  }
}

// Captcha endpoint (Bluefox.email compatible)
app.get('/v1/captcha', async (req, res) => {
  const captchaText = generateCaptchaText()
  const probe = crypto.randomUUID()
  const svg = generateCaptchaSVG(captchaText)
  
  // Store captcha with expiration (5 minutes)
  captchaStore.set(probe, {
    text: captchaText.toLowerCase(),
    expires: Date.now() + 5 * 60 * 1000 // 5 minutes
  })
  
  // Clean up expired captchas
  const now = Date.now()
  for (const [key, value] of captchaStore.entries()) {
    if (value.expires < now) {
      captchaStore.delete(key)
    }
  }
  
  res.json({
    result: {
      data: svg,
      probe: probe
    }
  })
})

// Rate limiting middleware
function rateLimitMiddleware(req, res, next) {
  const ip = req.ip || req.connection.remoteAddress
  const now = Date.now()
  const limit = 10 // requests per minute
  const window = 60 * 1000 // 1 minute
  
  if (!rateLimitStore.has(ip)) {
    rateLimitStore.set(ip, { count: 1, resetTime: now + window })
    return next()
  }
  
  const userData = rateLimitStore.get(ip)
  if (now > userData.resetTime) {
    userData.count = 1
    userData.resetTime = now + window
    return next()
  }
  
  if (userData.count >= limit) {
    return res.status(429).json({ 
      error: 'Too many requests. Please try again later.' 
    })
  }
  
  userData.count++
  next()
}

// Verify captcha function
function verifyCaptcha(captchaText, captchaProbe) {
  if (!captchaText || !captchaProbe) {
    return { valid: false, error: 'Missing captcha data' }
  }
  
  const stored = captchaStore.get(captchaProbe)
  if (!stored) {
    return { valid: false, error: 'Invalid or expired captcha' }
  }
  
  if (Date.now() > stored.expires) {
    captchaStore.delete(captchaProbe)
    return { valid: false, error: 'Captcha expired' }
  }
  
  const isValid = stored.text === captchaText.toLowerCase().trim()
  
  // Remove used captcha
  captchaStore.delete(captchaProbe)
  
  return { 
    valid: isValid, 
    error: isValid ? null : 'Incorrect captcha' 
  }
}

// 1. GET /check-dmarc?domain=example.com
app.get('/check-dmarc', async (req, res) => {
  const { domain } = req.query
  if (!domain) return res.status(400).json({ error: 'Missing domain parameter' })

  const txtRecords = await resolver.resolveTxt(`_dmarc.${domain}`)
  const flatRecords = txtRecords.map(entry => entry.join(''))
  const dmarcRecord = flatRecords.find(txt => txt.startsWith('v=DMARC1'))

  if (!dmarcRecord) {
    return res.json({ found: false, record: null, message: 'DMARC record not found' })
  }

  return res.json({ found: true, record: dmarcRecord })
})

// 2. POST /analyze-dmarc with { record: "v=DMARC1; p=..." }
app.post('/analyze-dmarc', rateLimitMiddleware, async (req, res) => {
  const { record, captchaText, captchaProbe } = req.body
  
  if (!record) {
    return res.status(400).json({ error: 'Missing DMARC record in request body' })
  }

  // Verify captcha if provided
  if (captchaText && captchaProbe) {
    const captchaResult = verifyCaptcha(captchaText, captchaProbe)
    if (!captchaResult.valid) {
      return res.status(400).json({ error: captchaResult.error })
    }
  }

  if (!record.includes('v=DMARC1')) {
    return res.status(400).json({ error: 'Invalid DMARC record: must contain v=DMARC1' })
  }

  const analysis = analyzeDMARC(record)
  
  return res.json({
    success: true,
    rawRecord: record,
    ...analysis
  })
})

// 3. GET /analyze-dmarc-by-domain?domain=example.com
app.get('/analyze-dmarc-by-domain', rateLimitMiddleware, async (req, res) => {
  const { domain, captchaText, captchaProbe } = req.query
  if (!domain) return res.status(400).json({ error: 'Missing domain parameter' })

  // Verify captcha if provided
  if (captchaText && captchaProbe) {
    const captchaResult = verifyCaptcha(captchaText, captchaProbe)
    if (!captchaResult.valid) {
      return res.status(400).json({ error: captchaResult.error })
    }
  }

  const txtRecords = await resolver.resolveTxt(`_dmarc.${domain}`)
  const flatRecords = txtRecords.map(entry => entry.join(''))
  const dmarcRecord = flatRecords.find(txt => txt.startsWith('v=DMARC1'))

  if (!dmarcRecord) {
    return res.status(404).json({ 
      success: false,
      error: 'DMARC record not found',
      domain,
      checkedRecord: `_dmarc.${domain}`
    })
  }

  const analysis = analyzeDMARC(dmarcRecord)

  return res.json({
    success: true,
    domain,
    checkedRecord: `_dmarc.${domain}`,
    rawRecord: dmarcRecord,
    ...analysis
  })
})

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ 
    status: 'healthy', 
    service: 'DMARC Analyzer API',
    version: '1.0.0',
    timestamp: new Date().toISOString(),
    company: 'Bluefox.email',
    endpoints: [
      'GET /health',
      'GET /v1/captcha',
      'GET /check-dmarc?domain=example.com',
      'POST /analyze-dmarc',
      'GET /analyze-dmarc-by-domain?domain=example.com',
      'POST /analyze-dmarc-with-captcha'
    ]
  })
})

// Enhanced endpoint with mandatory captcha verification
app.post('/analyze-dmarc-with-captcha', rateLimitMiddleware, async (req, res) => {
  const { record, captchaText, captchaProbe } = req.body
  
  if (!record) {
    return res.status(400).json({ error: 'Missing DMARC record in request body' })
  }

  if (!captchaText || !captchaProbe) {
    return res.status(400).json({ error: 'Captcha verification required' })
  }

  // Verify captcha
  const captchaResult = verifyCaptcha(captchaText, captchaProbe)
  if (!captchaResult.valid) {
    return res.status(400).json({ error: captchaResult.error })
  }

  if (!record.includes('v=DMARC1')) {
    return res.status(400).json({ error: 'Invalid DMARC record: must contain v=DMARC1' })
  }

  const analysis = analyzeDMARC(record)
  
  return res.json({
    success: true,
    rawRecord: record,
    captchaVerified: true,
    ...analysis
  })
})

app.listen(PORT, () => {
  console.log(`🚀 DMARC Analyzer API running at http://localhost:${PORT}`)
  console.log(`📧 Bluefox.email DMARC Tool Backend`)
  console.log(`🔍 Health check: http://localhost:${PORT}/health`)
  console.log(`🤖 Captcha endpoint: http://localhost:${PORT}/v1/captcha`)
  console.log(`📋 Available endpoints:`)
  console.log(`   GET  /health`)
  console.log(`   GET  /v1/captcha`)
  console.log(`   GET  /check-dmarc?domain=example.com`)
  console.log(`   POST /analyze-dmarc`)
  console.log(`   POST /analyze-dmarc-with-captcha (captcha required)`)
  console.log(`   GET  /analyze-dmarc-by-domain?domain=example.com`)
  console.log(``)
  console.log(`✨ Features:`)
  console.log(`   • Express Async API wrapper for better error handling`)
  console.log(`   • Bluefox.email compatible captcha system`)
  console.log(`   • Rate limiting protection`)
  console.log(`   • Enhanced CORS for frontend integration`)
})
