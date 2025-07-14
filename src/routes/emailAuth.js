// src/routes/emailAuth.js
import express from 'express'
import { analyzeDMARC } from '../services/dmarcService.js'
import { analyzeSPF } from '../services/spfService.js'
import { analyzeDKIM } from '../services/dkimService.js'
import { analyzeMX } from '../services/mxService.js'
import { analyzeEmailSecurity } from '../services/emailSecurityService.js'
import { rateLimitMiddleware } from '../utils/rateLimit.js'

const router = express.Router()

// Apply rate limiting to all routes
router.use(rateLimitMiddleware)

// DMARC Analysis Endpoint
router.post('/analyze-dmarc', async (req, res) => {
  try {
    const { domain } = req.body

    if (!domain) {
      return res.status(400).json({
        success: false,
        error: 'Domain is required'
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
    res.json(result)

  } catch (error) {
    console.error('DMARC analysis error:', error)
    res.status(500).json({
      success: false,
      error: 'Failed to analyze DMARC record'
    })
  }
})

// SPF Analysis Endpoint
router.post('/analyze-spf', async (req, res) => {
  try {
    const { domain } = req.body

    if (!domain) {
      return res.status(400).json({
        success: false,
        error: 'Domain is required'
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
    res.json(result)

  } catch (error) {
    console.error('SPF analysis error:', error)
    res.status(500).json({
      success: false,
      error: 'Failed to analyze SPF record'
    })
  }
})

// DKIM Analysis Endpoint
router.post('/analyze-dkim', async (req, res) => {
  try {
    const { domain, selector = 'default' } = req.body

    if (!domain) {
      return res.status(400).json({
        success: false,
        error: 'Domain is required'
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
    res.json(result)

  } catch (error) {
    console.error('DKIM analysis error:', error)
    res.status(500).json({
      success: false,
      error: 'Failed to analyze DKIM record'
    })
  }
})

// MX Analysis Endpoint
router.post('/analyze-mx', async (req, res) => {
  try {
    const { domain } = req.body

    if (!domain) {
      return res.status(400).json({
        success: false,
        error: 'Domain is required'
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
    res.json(result)

  } catch (error) {
    console.error('MX analysis error:', error)
    res.status(500).json({
      success: false,
      error: 'Failed to analyze MX records'
    })
  }
})

// Comprehensive Email Security Analysis Endpoint
router.post('/analyze-email-security', async (req, res) => {
  try {
    const { domain, dkimSelector = 'default' } = req.body

    if (!domain) {
      return res.status(400).json({
        success: false,
        error: 'Domain is required'
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
    res.json(result)

  } catch (error) {
    console.error('Email security analysis error:', error)
    res.status(500).json({
      success: false,
      error: 'Failed to analyze email security'
    })
  }
})

// Legacy DMARC endpoint for backward compatibility
router.post('/analyze-dmarc-by-domain', async (req, res) => {
  try {
    const { domain } = req.body

    if (!domain) {
      return res.status(400).json({
        success: false,
        error: 'Domain is required'
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
    res.json(result)

  } catch (error) {
    console.error('Legacy DMARC analysis error:', error)
    res.status(500).json({
      success: false,
      error: 'Failed to analyze DMARC record'
    })
  }
})

export default router
