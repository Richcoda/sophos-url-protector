import { SophosURLProtector } from '../lib/sophos-protector.js';
import CryptoJS from 'crypto-js';

const getSecretKey = () => {
  const secretKey = process.env.SECRET_KEY;
  
  console.log('🔑 Resolve - SECRET_KEY validation:');
  console.log('   - Available:', !!secretKey);
  console.log('   - Length:', secretKey ? secretKey.length : 0);
  
  if (!secretKey) {
    throw new Error('SECRET_KEY environment variable is not configured');
  }
  
  return secretKey;
};

export default async function handler(req, res) {
  // Add request ID for tracking
  const requestId = Date.now().toString(36) + Math.random().toString(36).substr(2);
  console.log(`\n=== RESOLUTION DOMAIN - REQUEST ${requestId} ===`);

  if (req.method !== 'GET') {
    console.log(`❌ Invalid method for resolve request ${requestId}:`, req.method);
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    console.log(`📨 Processing resolve request ${requestId}`);
    console.log('🌐 This is the RESOLUTION DOMAIN');
    
    const { d, u, p, i, t, h, s } = req.query;

    console.log('📋 Query parameters received:');
    console.log('   d:', d);
    console.log('   u length:', u?.length);
    console.log('   p:', p);
    console.log('   i length:', i?.length);
    console.log('   t length:', t?.length);
    console.log('   h length:', h?.length);
    console.log('   s length:', s?.length);

    // Validate required parameters
    if (!d || !u || !p || !i || !t || !h || !s) {
      const missing = [];
      if (!d) missing.push('d');
      if (!u) missing.push('u');
      if (!p) missing.push('p');
      if (!i) missing.push('i');
      if (!t) missing.push('t');
      if (!h) missing.push('h');
      if (!s) missing.push('s');
      
      console.error(`❌ Missing parameters in request ${requestId}:`, missing);
      
      return res.status(400).send(`
        <!DOCTYPE html>
        <html>
        <head>
          <title>Secure Link - Error</title>
          <meta charset="utf-8">
          <meta name="viewport" content="width=device-width, initial-scale=1">
          <link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><defs><linearGradient id='grad' x1='0%' y1='0%' x2='0%' y2='100%'><stop offset='0%' style='stop-color:%234F46E5;stop-opacity:1' /><stop offset='100%' style='stop-color:%237C3AED;stop-opacity:1' /></linearGradient></defs><path d='M50 10 L80 25 L80 40 C80 65 65 80 50 85 C35 80 20 65 20 40 L20 25 Z' fill='url(%23grad)' stroke='%233730A3' stroke-width='2'/><rect x='40' y='45' width='20' height='20' rx='3' fill='white' stroke='%231E1B4B' stroke-width='1.5'/><path d='M45 45 L45 35 C45 30 47 27 50 27 C53 27 55 30 55 35 L55 45' fill='none' stroke='%231E1B4B' stroke-width='2' stroke-linecap='round'/></svg>">
          <style>
            body { 
              font-family: 'Segoe UI', system-ui, sans-serif; 
              max-width: 600px; 
              margin: 0 auto;
              padding: 20px;
              background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
              min-height: 100vh;
              display: flex;
              align-items: center;
              justify-content: center;
              color: white;
            }
            .error-card { 
              background: rgba(255,255,255,0.95);
              color: #333;
              padding: 40px; 
              border-radius: 15px; 
              box-shadow: 0 20px 40px rgba(0,0,0,0.1);
              text-align: center;
              width: 100%;
            }
            h1 { 
              font-size: 2.5rem; 
              margin-bottom: 20px;
              color: #dc3545;
            }
            p {
              font-size: 1.1rem;
              margin-bottom: 25px;
              line-height: 1.6;
            }
          </style>
        </head>
        <body>
          <div class="error-card">
            <h1>🔒 Invalid Secure Link</h1>
            <p>The secure link is missing required security parameters.</p>
            <p><small>Error: Missing ${missing.join(', ')}</small></p>
          </div>
        </body>
        </html>
      `);
    }

    console.log('🛡️ Initializing URL protector for resolution...');
    const protector = new SophosURLProtector(getSecretKey());
    console.log('✅ URL protector initialized on resolution domain');

    const result = await protector.resolveProtectedURL({
      d, u, p, i, t, h, s
    });

    console.log(`✅ Resolve request ${requestId} completed successfully`);
    console.log('   Redirecting to:', result.originalURL);

    // Redirect to the original URL
    res.redirect(302, result.originalURL);

  } catch (error) {
    console.error(`❌ Resolve request ${requestId} failed:`, {
      message: error.message,
      stack: error.stack,
      queryParams: Object.keys(req.query)
    });
    
    res.status(400).send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>Secure Link - Access Denied</title>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><defs><linearGradient id='grad' x1='0%' y1='0%' x2='0%' y2='100%'><stop offset='0%' style='stop-color:%234F46E5;stop-opacity:1' /><stop offset='100%' style='stop-color:%237C3AED;stop-opacity:1' /></linearGradient></defs><path d='M50 10 L80 25 L80 40 C80 65 65 80 50 85 C35 80 20 65 20 40 L20 25 Z' fill='url(%23grad)' stroke='%233730A3' stroke-width='2'/><rect x='40' y='45' width='20' height='20' rx='3' fill='white' stroke='%231E1B4B' stroke-width='1.5'/><path d='M45 45 L45 35 C45 30 47 27 50 27 C53 27 55 30 55 35 L55 45' fill='none' stroke='%231E1B4B' stroke-width='2' stroke-linecap='round'/></svg>">
        <style>
          body { 
            font-family: 'Segoe UI', system-ui, sans-serif; 
            max-width: 600px; 
            margin: 0 auto;
            padding: 20px;
            background: linear-gradient(135deg, #ff6b6b 0%, #ee5a24 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
          }
          .error-card { 
            background: rgba(255,255,255,0.95);
            color: #333;
            padding: 40px; 
            border-radius: 15px; 
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            text-align: center;
            width: 100%;
          }
          h1 { 
            font-size: 2.5rem; 
            margin-bottom: 20px;
            color: #dc3545;
          }
          .reasons { 
            text-align: left; 
            display: inline-block; 
            margin: 25px 0;
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
          }
          .reasons ul {
            margin: 0;
            padding-left: 20px;
          }
          .reasons li {
            margin-bottom: 8px;
            line-height: 1.5;
          }
        </style>
      </head>
      <body>
        <div class="error-card">
          <h1>🚫 Secure Link Access Denied</h1>
          <p><strong>${error.message}</strong></p>
          <div class="reasons">
            <p>Possible reasons:</p>
            <ul>
              <li>🔸 Link has expired</li>
              <li>🔸 Maximum clicks reached</li>
              <li>🔸 Security threat detected</li>
              <li>🔸 Invalid or tampered link</li>
              <li>🔸 Protection rules violation</li>
              <li>🔸 Signature verification failed</li>
            </ul>
          </div>
        </div>
      </body>
      </html>
    `);
  } finally {
    console.log(`=== END RESOLUTION REQUEST ${requestId} ===\n`);
  }
}