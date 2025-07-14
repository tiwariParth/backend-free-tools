// src/routes/emailAuth.js
import express from 'express'
import { 
  analyzeDMARC, 
  analyzeSPF, 
  analyzeDKIM, 
  analyzeMX, 
  analyzeEmailSecurity 
} from '../services/emailAuth.js'
import { verifyCaptcha } from '../utils/captcha.js'
import { rateLimitMiddleware } from '../utils/rateLimit.js'

const router = express.Router()

// Bluefox.email captcha verification
async function verifyBluefoxCaptcha(captchaText, captchaProbe) {
  try {
    // For now, we'll accept any non-empty captcha text as valid
    // In production, you would implement the actual verification logic
    // that matches your Bluefox.email captcha system
    if (!captchaText || !captchaProbe) {
      return false
    }
    
    // Basic validation - captcha text should be at least 3 characters
    if (captchaText.trim().length < 3) {
      return false
    }
    
    // TODO: Implement actual Bluefox captcha verification
    // For now, return true for non-empty inputs
    console.log('Captcha verification - Text:', captchaText, 'Probe:', captchaProbe?.substring(0, 20) + '...')
    return true
  } catch (error) {
    console.error('Captcha verification error:', error)
    return false
  }
}

// Apply rate limiting to all email auth routes
router.use(rateLimitMiddleware)

// DMARC Checker Route
router.post('/analyze-dmarc', async (req, res) => {
  const { domain, captchaToken, captchaUserInput } = req.body

  if (!domain) {
    return res.status(400).json({ 
      success: false, 
      error: 'Domain is required' 
    })
  }

  // Verify captcha
  const captchaValid = verifyCaptcha(captchaToken, captchaUserInput)
  if (!captchaValid) {
    return res.status(400).json({ 
      success: false, 
      error: 'Invalid captcha. Please try again.' 
    })
  }

  // Clean and validate domain
  const cleanDomain = domain.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/^www\./, '').split('/')[0]
  
  if (!cleanDomain || cleanDomain.length === 0) {
    return res.status(400).json({ 
      success: false, 
      error: 'Please enter a valid domain name' 
    })
  }

  const result = await analyzeDMARC(cleanDomain)
  return res.json(result)
})

// SPF Checker Route
router.post('/analyze-spf', async (req, res) => {
  const { domain, captchaText, captchaProbe } = req.body

  if (!domain) {
    return res.status(400).json({ 
      success: false, 
      error: 'Domain is required' 
    })
  }

  // Verify captcha with Bluefox.email format
  const captchaValid = await verifyBluefoxCaptcha(captchaText, captchaProbe)
  if (!captchaValid) {
    return res.status(400).json({ 
      success: false, 
      error: 'Invalid captcha. Please try again.' 
    })
  }

  // Clean and validate domain
  const cleanDomain = domain.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/^www\./, '').split('/')[0]
  
  if (!cleanDomain || cleanDomain.length === 0) {
    return res.status(400).json({ 
      success: false, 
      error: 'Please enter a valid domain name' 
    })
  }

  const result = await analyzeSPF(cleanDomain)
  return res.json(result)
})

// DKIM Checker Route
router.post('/analyze-dkim', async (req, res) => {
  const { domain, selector = 'default', captchaText, captchaProbe } = req.body

  if (!domain) {
    return res.status(400).json({ 
      success: false, 
      error: 'Domain is required' 
    })
  }

  // Verify captcha with Bluefox.email format
  const captchaValid = await verifyBluefoxCaptcha(captchaText, captchaProbe)
  if (!captchaValid) {
    return res.status(400).json({ 
      success: false, 
      error: 'Invalid captcha. Please try again.' 
    })
  }

  // Clean and validate domain
  const cleanDomain = domain.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/^www\./, '').split('/')[0]
  
  if (!cleanDomain || cleanDomain.length === 0) {
    return res.status(400).json({ 
      success: false, 
      error: 'Please enter a valid domain name' 
    })
  }

  const result = await analyzeDKIM(cleanDomain, selector)
  return res.json(result)
})

// MX Checker Route
router.post('/analyze-mx', async (req, res) => {
  const { domain, captchaText, captchaProbe } = req.body

  if (!domain) {
    return res.status(400).json({ 
      success: false, 
      error: 'Domain is required' 
    })
  }

  // Verify captcha with Bluefox.email format
  const captchaValid = await verifyBluefoxCaptcha(captchaText, captchaProbe)
  if (!captchaValid) {
    return res.status(400).json({ 
      success: false, 
      error: 'Invalid captcha. Please try again.' 
    })
  }

  // Clean and validate domain
  const cleanDomain = domain.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/^www\./, '').split('/')[0]
  
  if (!cleanDomain || cleanDomain.length === 0) {
    return res.status(400).json({ 
      success: false, 
      error: 'Please enter a valid domain name' 
    })
  }

  const result = await analyzeMX(cleanDomain)
  return res.json(result)
})

// Comprehensive Email Security Check Route
router.post('/analyze-email-security', async (req, res) => {
  const { domain, dkimSelector = 'default', captchaText, captchaProbe } = req.body

  if (!domain) {
    return res.status(400).json({ 
      success: false, 
      error: 'Domain is required' 
    })
  }

  // Verify captcha with Bluefox.email format
  const captchaValid = await verifyBluefoxCaptcha(captchaText, captchaProbe)
  if (!captchaValid) {
    return res.status(400).json({ 
      success: false, 
      error: 'Invalid captcha. Please try again.' 
    })
  }

  // Clean and validate domain
  const cleanDomain = domain.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/^www\./, '').split('/')[0]
  
  if (!cleanDomain || cleanDomain.length === 0) {
    return res.status(400).json({ 
      success: false, 
      error: 'Please enter a valid domain name' 
    })
  }

  const result = await analyzeEmailSecurity(cleanDomain, dkimSelector)
  return res.json(result)
})

// Legacy route for backward compatibility
router.post('/analyze-dmarc-by-domain', async (req, res) => {
  const { domain, captchaText, captchaProbe } = req.body

  if (!domain) {
    return res.status(400).json({ 
      success: false, 
      error: 'Domain is required' 
    })
  }

  // Verify captcha with Bluefox.email format
  const captchaValid = await verifyBluefoxCaptcha(captchaText, captchaProbe)
  if (!captchaValid) {
    return res.status(400).json({ 
      success: false, 
      error: 'Invalid captcha. Please try again.' 
    })
  }

  // Clean and validate domain
  const cleanDomain = domain.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/^www\./, '').split('/')[0]
  
  if (!cleanDomain || cleanDomain.length === 0) {
    return res.status(400).json({ 
      success: false, 
      error: 'Please enter a valid domain name' 
    })
  }

  const result = await analyzeDMARC(cleanDomain)
  return res.json(result)
})

export default router
