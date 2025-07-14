import express from 'express'
import cors from 'cors'
import expressAsyncApi from 'express-async-api'

// Import route modules
import emailAuthRoutes from './src/routes/emailAuth.js'
import captchaRoutes from './src/routes/captcha.js'

const app = express()
const PORT = process.env.PORT || 3000

// Apply express-async-api to the main app
expressAsyncApi(app)

// Middleware
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type']
}))

app.use(express.json({ limit: '10mb' }))

// Routes
app.get('/health', (req, res) => {
  res.json({ 
    status: 'healthy', 
    service: 'Email Authentication Suite API',
    version: '2.0.0',
    timestamp: new Date().toISOString(),
    company: 'Bluefox.email',
    endpoints: [
      'GET /health',
      'GET /api/v1/captcha',
      'POST /api/analyze-dmarc',
      'POST /api/analyze-spf',
      'POST /api/analyze-dkim',
      'POST /api/analyze-mx',
      'POST /api/analyze-email-security',
      'POST /api/analyze-dmarc-by-domain (legacy)'
    ]
  })
})

// Mount route modules
app.use('/api/v1', captchaRoutes)
app.use('/api', emailAuthRoutes)

app.listen(PORT, () => {
  console.log(`🚀 Email Authentication Suite API running at http://localhost:${PORT}`)
  console.log(`📧 Bluefox.email Multi-Protocol Email Security Tool`)
  console.log(`🔍 Health check: http://localhost:${PORT}/health`)
  console.log(``)
  console.log(`📋 Available endpoints:`)
  console.log(`   GET  /health`)
  console.log(`   GET  /api/v1/captcha`)
  console.log(`   POST /api/analyze-dmarc`)
  console.log(`   POST /api/analyze-spf`)
  console.log(`   POST /api/analyze-dkim`)
  console.log(`   POST /api/analyze-mx`)
  console.log(`   POST /api/analyze-email-security (comprehensive)`)
  console.log(`   POST /api/analyze-dmarc-by-domain (legacy)`)
  console.log(``)
  console.log(`✨ Features:`)
  console.log(`   • DMARC, SPF, DKIM, and MX record analysis`)
  console.log(`   • Comprehensive email security scoring`)
  console.log(`   • Express Async API wrapper for better error handling`)
  console.log(`   • Bluefox.email compatible captcha system`)
  console.log(`   • Rate limiting protection (10 req/min)`)
  console.log(`   • Enhanced CORS for frontend integration`)
  console.log(`   • Mailauth library integration for advanced analysis`)
  console.log(`   • Modular architecture for maintainability`)
})
