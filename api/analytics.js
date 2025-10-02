import { SophosURLProtector } from '../lib/sophos-protector.js';
import CryptoJS from 'crypto-js';

const getSecretKey = () => {
  const secretKey = process.env.SECRET_KEY;
  if (!secretKey) {
    throw new Error('SECRET_KEY environment variable is not configured');
  }
  return secretKey;
};

// Get dynamic base URL from request
const getDynamicBaseURL = (req) => {
  const host = req.headers['x-forwarded-host'] || req.headers['host'];
  const protocol = process.env.NODE_ENV === 'production' ? 'https' : 'http';
  const baseURL = `${protocol}://${host}`;
  
  console.log('🌐 Analytics - Dynamic base URL:', baseURL);
  return baseURL;
};

export default async function handler(req, res) {
  // Add request ID for tracking
  const requestId = Date.now().toString(36) + Math.random().toString(36).substr(2);
  console.log(`\n=== ANALYTICS REQUEST ${requestId} ===`);

  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Content-Type', 'application/json');

  if (req.method === 'OPTIONS') {
    console.log(`🔄 Analytics CORS preflight for request ${requestId}`);
    return res.status(200).end();
  }

  if (req.method !== 'GET') {
    console.log(`❌ Invalid method for analytics request ${requestId}:`, req.method);
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const { id } = req.query;

    console.log(`📊 Analytics request for ID: ${id}`);

    if (!id) {
      console.log('❌ Missing URL ID in analytics request');
      return res.status(400).json({ error: 'URL ID is required' });
    }

    const protector = new SophosURLProtector(getSecretKey());
    
    // Override base URL with dynamic detection
    protector.baseURL = getDynamicBaseURL(req);
    
    console.log('🛡️ Getting URL analytics...');
    const analytics = protector.getURLAnalytics(id);
    
    console.log('✅ Analytics retrieved successfully');
    console.log('📈 Analytics data:', analytics);

    // Enhanced response with calculated fields
    const enhancedAnalytics = {
      ...analytics,
      protectionLevel: getProtectionLevelDescription(analytics.protectionMode),
      timeRemaining: getTimeRemaining(analytics.expires),
      status: getURLStatus(analytics),
      createdFromNow: getTimeFromNow(analytics.created),
      isActive: analytics.isActive !== false, // Default to true if not specified
      isExpired: analytics.isExpired || false
    };

    res.status(200).json({
      success: true,
      analytics: enhancedAnalytics,
      requestId: requestId
    });

  } catch (error) {
    console.error(`❌ Analytics request ${requestId} failed:`, error.message);
    
    res.status(404).json({ 
      success: false, 
      error: error.message,
      requestId: requestId
    });
  } finally {
    console.log(`=== END ANALYTICS REQUEST ${requestId} ===\n`);
  }
}

function getProtectionLevelDescription(mode) {
  const levels = {
    'l': {
      name: 'Low Protection',
      description: 'Basic encryption with standard security',
      features: ['URL Encryption', 'Basic Validation']
    },
    'm': {
      name: 'Medium Protection', 
      description: 'Standard security with enhanced validation',
      features: ['URL Encryption', 'Hash Verification', 'Signature Validation']
    },
    'h': {
      name: 'High Protection',
      description: 'Enhanced security with comprehensive checks',
      features: ['URL Encryption', 'Hash Verification', 'Signature Validation', 'Security Scanning']
    }
  };
  return levels[mode] || {
    name: 'Unknown Protection',
    description: 'Protection level not specified',
    features: ['Basic Security']
  };
}

function getTimeRemaining(expires) {
  if (!expires) return 'Unknown';
  
  const now = new Date();
  const expiresDate = new Date(expires);
  const diff = expiresDate - now;
  
  if (diff <= 0) return 'Expired';
  
  const days = Math.floor(diff / (1000 * 60 * 60 * 24));
  const hours = Math.floor((diff % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
  const minutes = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));
  
  if (days > 0) {
    return `${days} day${days > 1 ? 's' : ''} ${hours} hour${hours > 1 ? 's' : ''} remaining`;
  } else if (hours > 0) {
    return `${hours} hour${hours > 1 ? 's' : ''} ${minutes} minute${minutes > 1 ? 's' : ''} remaining`;
  } else {
    return `${minutes} minute${minutes > 1 ? 's' : ''} remaining`;
  }
}

function getTimeFromNow(date) {
  if (!date) return 'Unknown';
  
  const now = new Date();
  const targetDate = new Date(date);
  const diff = now - targetDate;
  
  const minutes = Math.floor(diff / (1000 * 60));
  const hours = Math.floor(diff / (1000 * 60 * 60));
  const days = Math.floor(diff / (1000 * 60 * 60 * 24));
  
  if (days > 0) {
    return `${days} day${days > 1 ? 's' : ''} ago`;
  } else if (hours > 0) {
    return `${hours} hour${hours > 1 ? 's' : ''} ago`;
  } else if (minutes > 0) {
    return `${minutes} minute${minutes > 1 ? 's' : ''} ago`;
  } else {
    return 'Just now';
  }
}

function getURLStatus(analytics) {
  if (analytics.isExpired) {
    return 'expired';
  }
  
  if (analytics.isActive === false) {
    return 'deactivated';
  }
  
  if (analytics.maxClicks && analytics.clicks >= analytics.maxClicks) {
    return 'max_clicks_reached';
  }
  
  return 'active';
}