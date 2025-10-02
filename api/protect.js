import { SophosURLProtector } from '../lib/sophos-protector.js';

// Get secret key from environment with proper error handling
const getSecretKey = () => {
  const secretKey = process.env.SECRET_KEY;
  if (!secretKey) {
    throw new Error('SECRET_KEY environment variable is not configured. Please set it in Vercel environment variables.');
  }
  return secretKey;
};

export default async function handler(req, res) {
  // Set CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Content-Type', 'application/json');

  // Handle CORS preflight
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ 
      success: false, 
      error: 'Method not allowed. Use POST.' 
    });
  }

  try {
    const { url, expiresIn = 720, maxClicks, protectionMode = 'm' } = req.body;

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

    // Initialize protector with secret key
    const protector = new SophosURLProtector(getSecretKey());

    // Validate and parse options
    const hours = parseInt(expiresIn);
    if (isNaN(hours) || hours < 1) {
      return res.status(400).json({ 
        success: false, 
        error: 'Invalid expiration time' 
      });
    }

    if (hours > 24 * 365) {
      return res.status(400).json({ 
        success: false, 
        error: 'Maximum expiration time is 1 year' 
      });
    }

    const options = {
      expiresIn: hours * 60 * 60 * 1000,
      protectionMode
    };
    
    if (maxClicks) {
      const clicks = parseInt(maxClicks);
      if (isNaN(clicks) || clicks < 1) {
        return res.status(400).json({ 
          success: false, 
          error: 'Invalid max clicks value' 
        });
      }
      options.maxClicks = clicks;
    }

    // Protect the URL
    const result = protector.protectURL(url, options);
    
    res.status(200).json({
      success: true,
      protectedURL: result.protectedURL,
      urlId: result.urlId,
      expiresAt: result.expiresAt,
      protectionMode: result.protectionMode,
      analytics: result.analytics
    });

  } catch (error) {
    console.error('Protection error:', error);
    res.status(500).json({ 
      success: false, 
      error: error.message 
    });
  }
}