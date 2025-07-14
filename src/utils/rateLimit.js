// src/utils/rateLimit.js

// Rate limiting store (in production, use Redis)
const rateLimitStore = new Map()

// Rate limiting middleware
export function rateLimitMiddleware(req, res, next) {
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
