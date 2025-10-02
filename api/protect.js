import { config } from '../lib/config.js';
import { SophosURLProtector } from '../lib/sophos-protector.js';

export default async function handler(req, res) {
  res.setHeader('Content-Type', 'application/json');
  
  try {
    console.log('🔑 Using secret key:', config.secretKey.substring(0, 10) + '...');
    
    const { url, expiresIn = 720, maxClicks, protectionMode = 'm' } = req.body;

    if (!url) {
      return res.status(400).json({ error: 'URL is required' });
    }

    const protector = new SophosURLProtector(config.secretKey, config.domain);

    const options = {
      expiresIn: parseInt(expiresIn) * 60 * 60 * 1000,
      protectionMode
    };
    
    if (maxClicks) {
      options.maxClicks = parseInt(maxClicks);
    }

    const result = protector.protectURL(url, options);
    
    console.log('✅ URL protected:', result.urlId);
    
    res.status(200).json({
      success: true,
      protectedURL: result.protectedURL,
      urlId: result.urlId,
      expiresAt: result.expiresAt,
      protectionMode: result.protectionMode,
      analytics: result.analytics
    });

  } catch (error) {
    console.error('❌ Protection error:', error);
    res.status(500).json({ 
      success: false, 
      error: error.message 
    });
  }
}