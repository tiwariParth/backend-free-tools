// src/utils/captcha.js
import crypto from 'crypto'

// In-memory captcha store (in production, use Redis or database)
const captchaStore = new Map()

// Generate captcha SVG
export function generateCaptchaSVG(text) {
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
export function generateCaptchaText() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
  let result = ''
  for (let i = 0; i < 5; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length))
  }
  return result
}

// Create captcha
export function createCaptcha() {
  const captchaText = generateCaptchaText()
  const token = crypto.randomUUID()
  const svg = generateCaptchaSVG(captchaText)
  
  // Store captcha with expiration (5 minutes)
  captchaStore.set(token, {
    text: captchaText.toLowerCase(),
    expires: Date.now() + 5 * 60 * 1000 // 5 minutes
  })
  
  // Clean up expired captchas
  cleanupExpiredCaptchas()
  
  return {
    token: token,
    svg: svg
  }
}

// Verify captcha
export function verifyCaptcha(captchaToken, captchaUserInput) {
  if (!captchaUserInput || !captchaToken) {
    return false
  }
  
  const stored = captchaStore.get(captchaToken)
  if (!stored) {
    return false
  }
  
  if (Date.now() > stored.expires) {
    captchaStore.delete(captchaToken)
    return false
  }
  
  const isValid = stored.text === captchaUserInput.toLowerCase().trim()
  
  // Remove used captcha
  captchaStore.delete(captchaToken)
  
  return isValid
}

// Clean up expired captchas
function cleanupExpiredCaptchas() {
  const now = Date.now()
  for (const [key, value] of captchaStore.entries()) {
    if (value.expires < now) {
      captchaStore.delete(key)
    }
  }
}
