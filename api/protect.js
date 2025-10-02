import { SophosURLProtector } from '../lib/sophos-protector.js';

// Get secret key from environment with comprehensive validation
const getSecretKey = () => {
  const secretKey = process.env.SECRET_KEY;
  
  console.log('🔑 SECRET_KEY validation:');
  console.log('   - Available:', !!secretKey);
  console.log('   - Type:', typeof secretKey);
  console.log('   - Length:', secretKey ? secretKey.length : 0);
  
  if (!secretKey) {
    throw new Error('SECRET_KEY environment variable is not configured. Please set it in Vercel environment variables.');
  }
  
  if (typeof secretKey !== 'string') {
    throw new Error('SECRET_KEY must be a string');
  }
  
  if (secretKey.length < 10) {
    throw new Error('SECRET_KEY is too short. Please use a longer key (min 10 characters).');
  }
  
  console.log('✅ SECRET_KEY validation passed');
  return secretKey;
};

// Test CryptoJS functionality
const testCryptoJS = () => {
  try {
    console.log('🧪 Testing CryptoJS functionality...');
    const testKey = 'test-key-123';
    const testData = 'Hello, World!';
    
    const encrypted = CryptoJS.AES.encrypt(testData, testKey).toString();
    const decrypted = CryptoJS.AES.decrypt(encrypted, testKey).toString(CryptoJS.enc.Utf8);
    
    const success = decrypted === testData;
    console.log('✅ CryptoJS test:', success ? 'PASSED' : 'FAILED');
    
    return success;
  } catch (error) {
    console.error('❌ CryptoJS test failed:', error.message);
    return false;
  }
};

export default async function handler(req, res) {
  // Set CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Content-Type', 'application/json');

  // Add request ID for tracking
  const requestId = Date.now().toString(36) + Math.random().toString(36).substr(2);
  console.log(`\n=== NEW REQUEST ${requestId} ===`);

  // Handle CORS preflight
  if (req.method === 'OPTIONS') {
    console.log(`🔄 CORS preflight for request ${requestId}`);
    return res.status(200).end();
  }

  if (req.method !== 'POST') {
    console.log(`❌ Invalid method for request ${requestId}:`, req.method);
    return res.status(405).json({ 
      success: false, 
      error: 'Method not allowed. Use POST.' 
    });
  }

  try {
    console.log(`📨 Processing request ${requestId}`);
    
    // Parse request body
    let body;
    try {
      body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
      console.log('📝 Request body parsed successfully');
    } catch (parseError) {
      console.error('❌ JSON parse error:', parseError.message);
      return res.status(400).json({ 
        success: false, 
        error: 'Invalid JSON in request body' 
      });
    }

    const { url, expiresIn = 720, maxClicks, protectionMode = 'm' } = body;

    // Validate required fields
    if (!url) {
      console.log('❌ Missing URL in request');
      return res.status(400).json({ 
        success: false, 
        error: 'URL is required' 
      });
    }

    console.log('🌐 URL to protect:', url);

    // Validate URL format
    try {
      new URL(url);
      console.log('✅ URL format validation passed');
    } catch (error) {
      console.error('❌ Invalid URL format:', error.message);
      return res.status(400).json({ 
        success: false, 
        error: 'Invalid URL format' 
      });
    }

    // Test CryptoJS before proceeding
    console.log('🧪 Running CryptoJS health check...');
    const cryptoTest = testCryptoJS();
    if (!cryptoTest) {
      throw new Error('CryptoJS encryption test failed - library may not be working correctly');
    }

    // Initialize protector
    console.log('🛡️ Initializing URL protector...');
    const protector = new SophosURLProtector(getSecretKey());
    console.log('✅ URL protector initialized');

    // Validate and parse options
    const hours = parseInt(expiresIn);
    if (isNaN(hours) || hours < 1) {
      console.error('❌ Invalid expiration time:', expiresIn);
      return res.status(400).json({ 
        success: false, 
        error: 'Invalid expiration time' 
      });
    }

    if (hours > 24 * 365) {
      console.error('❌ Expiration time too long:', hours);
      return res.status(400).json({ 
        success: false, 
        error: 'Maximum expiration time is 1 year' 
      });
    }

    console.log('⏰ Expiration set to:', hours, 'hours');

    const options = {
      expiresIn: hours * 60 * 60 * 1000,
      protectionMode
    };
    
    if (maxClicks) {
      const clicks = parseInt(maxClicks);
      if (isNaN(clicks) || clicks < 1) {
        console.error('❌ Invalid max clicks:', maxClicks);
        return res.status(400).json({ 
          success: false, 
          error: 'Invalid max clicks value' 
        });
      }
      options.maxClicks = clicks;
      console.log('👆 Max clicks set to:', clicks);
    }

    // Protect the URL
    console.log('🔒 Starting URL protection process...');
    const result = protector.protectURL(url, options);
    console.log('✅ URL protection completed successfully');
    
    console.log(`🎉 Request ${requestId} completed successfully`);
    
    res.status(200).json({
      success: true,
      protectedURL: result.protectedURL,
      urlId: result.urlId,
      expiresAt: result.expiresAt,
      protectionMode: result.protectionMode,
      analytics: result.analytics,
      requestId: requestId
    });

  } catch (error) {
    console.error(`❌ Request ${requestId} failed:`, {
      message: error.message,
      stack: error.stack,
      secretKey: process.env.SECRET_KEY ? `SET (length: ${process.env.SECRET_KEY.length})` : 'MISSING'
    });
    
    res.status(500).json({ 
      success: false, 
      error: error.message,
      requestId: requestId
    });
  } finally {
    console.log(`=== END REQUEST ${requestId} ===\n`);
  }
}