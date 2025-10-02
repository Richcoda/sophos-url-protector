import { SophosURLProtector } from '../lib/sophos-protector.js';
import CryptoJS from 'crypto-js';

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
  console.log(`\n=== NEW PROTECT REQUEST ${requestId} ===`);

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
    console.log(`📨 Processing protect request ${requestId}`);
    
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

    // DEBUG: Analyze the generated protected URL
    console.log('🔍 Generated Protected URL Analysis:');
    try {
      const protectedURL = new URL(result.protectedURL);
      const params = protectedURL.searchParams;
      
      console.log('📊 URL Parameter Analysis:');
      console.log('   - u (encryptedData):', params.get('u')?.length, 'chars');
      console.log('   - t (securityToken):', params.get('t')?.length, 'chars');
      console.log('   - s (signature):', params.get('s')?.length, 'chars');
      console.log('   - i (urlId):', params.get('i')?.length, 'chars');
      console.log('   - h (hash):', params.get('h')?.length, 'chars');
      console.log('   - p (protection):', params.get('p'));
      console.log('   - d (domain):', params.get('d'));
      
      // Log the actual parameter values (truncated for security)
      console.log('📄 Parameter Samples (first 50 chars):');
      console.log('   - u sample:', params.get('u')?.substring(0, 50) + '...');
      console.log('   - t sample:', params.get('t')?.substring(0, 50) + '...');
      console.log('   - s sample:', params.get('s')?.substring(0, 50) + '...');
      
    } catch (urlError) {
      console.error('❌ Error analyzing protected URL:', urlError.message);
    }

    // Test the protected URL immediately to catch issues early
    console.log('🧪 Testing protected URL structure...');
    try {
      const testURL = new URL(result.protectedURL);
      const testParams = testURL.searchParams;
      
      // Verify all required parameters are present
      const requiredParams = ['d', 'u', 'p', 'i', 't', 'h', 's'];
      const missingParams = requiredParams.filter(param => !testParams.get(param));
      
      if (missingParams.length > 0) {
        console.error('❌ Missing parameters in protected URL:', missingParams);
      } else {
        console.log('✅ All required parameters present in protected URL');
      }
      
      // Verify parameter lengths are reasonable
      const paramLengths = {
        u: testParams.get('u')?.length,
        t: testParams.get('t')?.length,
        s: testParams.get('s')?.length,
        i: testParams.get('i')?.length,
        h: testParams.get('h')?.length
      };
      
      console.log('📏 Parameter lengths:', paramLengths);
      
      // Check for suspiciously short parameters
      Object.entries(paramLengths).forEach(([param, length]) => {
        if (length < 10) {
          console.warn(`⚠️  Parameter ${param} is very short: ${length} chars`);
        }
      });
      
    } catch (testError) {
      console.error('❌ Protected URL test failed:', testError.message);
    }

    console.log(`🎉 Request ${requestId} completed successfully`);
    console.log('📤 Response data:');
    console.log('   - protectedURL length:', result.protectedURL.length);
    console.log('   - urlId:', result.urlId);
    console.log('   - protectionMode:', result.protectionMode);
    console.log('   - expiresAt:', result.expiresAt);
    console.log('   - analytics URL:', result.analytics);
    
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
    console.log(`=== END PROTECT REQUEST ${requestId} ===\n`);
  }
}