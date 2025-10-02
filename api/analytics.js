import { SophosURLProtector } from '../lib/sophos-protector.js';

const getSecretKey = () => {
  const secretKey = process.env.SECRET_KEY;
  if (!secretKey) {
    throw new Error('SECRET_KEY environment variable is not configured');
  }
  return secretKey;
};

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Content-Type', 'application/json');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  if (req.method !== 'GET') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const { id } = req.query;

    if (!id) {
      return res.status(400).json({ error: 'URL ID is required' });
    }

    const protector = new SophosURLProtector(getSecretKey());
    const analytics = protector.getURLAnalytics(id);
    
    res.status(200).json({
      success: true,
      analytics: {
        ...analytics,
        protectionLevel: getProtectionLevelDescription(analytics.protectionMode),
        timeRemaining: getTimeRemaining(analytics.expires)
      }
    });
  } catch (error) {
    res.status(404).json({ 
      success: false, 
      error: error.message 
    });
  }
}

function getProtectionLevelDescription(mode) {
  const levels = {
    'l': 'Low Protection - Basic encryption',
    'm': 'Medium Protection - Standard security',
    'h': 'High Protection - Enhanced security'
  };
  return levels[mode] || 'Unknown';
}

function getTimeRemaining(expires) {
  const now = new Date();
  const expiresDate = new Date(expires);
  const diff = expiresDate - now;
  
  if (diff <= 0) return 'Expired';
  
  const days = Math.floor(diff / (1000 * 60 * 60 * 24));
  const hours = Math.floor((diff % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
  
  if (days > 0) {
    return `${days} day${days > 1 ? 's' : ''} ${hours} hour${hours > 1 ? 's' : ''} remaining`;
  }
  return `${hours} hour${hours > 1 ? 's' : ''} remaining`;
}