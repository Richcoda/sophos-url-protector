import { config } from '../lib/config.js';
import { SophosURLProtector } from '../lib/sophos-protector.js';

export default async function handler(req, res) {
  // Set JSON header immediately
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  // Handle CORS preflight
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  // Only allow POST
  if (req.method !== 'POST') {
    return res.status(405).json({ 
      success: false, 
      error: 'Method not allowed. Use POST.' 
    });
  }

  try {
    console.log('📨 Received protect request on Vercel');
    
    // Parse JSON body
    let body;
    try {
      body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    } catch (parseError) {
      return res.status(400).json({ 
        success: false, 
        error: 'Invalid JSON in request body' 
      });
    }

    const { url, expiresIn = 720, maxClicks, protectionMode = 'm' } = body;

    // Validate required fields
    if (!url) {
      return res.status(400).json({ 
        success: false, 
        error: 'URL is required' 
      });
    }

    // Validate URL format
    try {
      new URL(url);
    } catch (error) {
      return res.status(400).json({ 
        success: false, 
        error: 'Invalid URL format' 
      });
    }

    console.log('🔑 Using secret key on Vercel');
    const protector = new SophosURLProtector(config.secretKey, config.domain);

    // Validate expiration time
    const hours = parseInt(expiresIn);
    if (hours > 24 * 365) {
      return res.status(400).json({ 
        success: false, 
        error: 'Maximum expiration time is 1 year (8760 hours)' 
      });
    }

    const options = {
      expiresIn: hours * 60 * 60 * 1000,
      protectionMode
    };
    
    if (maxClicks) {
      options.maxClicks = parseInt(maxClicks);
    }

    const result = protector.protectURL(url, options);
    
    console.log('✅ URL protected on Vercel:', result.urlId);
    
    res.status(200).json({
      success: true,
      protectedURL: result.protectedURL,
      urlId: result.urlId,
      expiresAt: result.expiresAt,
      protectionMode: result.protectionMode,
      analytics: result.analytics,
      environment: 'vercel'
    });

  } catch (error) {
    console.error('❌ Vercel protection error:', error);
    res.status(500).json({ 
      success: false, 
      error: error.message,
      type: 'server_error'
    });
  }
}