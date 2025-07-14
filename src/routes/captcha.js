// src/routes/captcha.js
import express from 'express'
import { createCaptcha } from '../utils/captcha.js'

const router = express.Router()

// Captcha generation endpoint
router.get('/captcha', async (req, res) => {
  const { token, svg } = createCaptcha()
  
  res.json({
    success: true,
    token,
    svg
  })
})

export default router
