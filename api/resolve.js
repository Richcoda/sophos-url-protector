import { SophosURLProtector } from './lib/sophos-protector.js';
import { config } from './lib/config.js';

export default async function handler(req, res) {
  if (req.method !== 'GET') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    console.log('🔑 Resolving with secret key:', config.secretKey.substring(0, 10) + '...');
    
    const { d, u, p, i, t, h, s } = req.query;
    
    if (!d || !u || !p || !i || !t || !h || !s) {
      return res.status(400).send(`
        <!DOCTYPE html>
        <html>
        <head>
          <title>Sophos URL Protector - Error</title>
          <style>
            body { 
              font-family: 'Segoe UI', Arial, sans-serif; 
              max-width: 600px; 
              margin: 100px auto; 
              text-align: center; 
              background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
              color: white;
            }
            .error-card { 
              background: rgba(255,255,255,0.1); 
              backdrop-filter: blur(10px);
              padding: 40px; 
              border-radius: 15px; 
              box-shadow: 0 10px 30px rgba(0,0,0,0.3);
            }
            h1 { font-size: 2.5rem; margin-bottom: 20px; }
            a { 
              color: #4FC3F7; 
              text-decoration: none;
              font-weight: bold;
              margin-top: 20px;
              display: inline-block;
            }
          </style>
        </head>
        <body>
          <div class="error-card">
            <h1>🔒 Invalid Protected URL</h1>
            <p>The URL is missing required Sophos security parameters.</p>
            <a href="/">🛡️ Create a new protected URL</a>
          </div>
        </body>
        </html>
      `);
    }

    const protector = new SophosURLProtector(config.secretKey, config.domain);
    console.log('🔄 Resolving URL with params:', { d, p });

    const result = await protector.resolveProtectedURL({
      d, u, p, i, t, h, s
    });

    console.log('✅ URL resolved to:', result.originalURL);
    
    // Redirect to the original URL
    res.redirect(302, result.originalURL);

  } catch (error) {
    console.error('❌ Resolution error:', error.message);
    res.status(400).send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>Sophos URL Protector - Access Denied</title>
        <style>
          body { 
            font-family: 'Segoe UI', Arial, sans-serif; 
            max-width: 600px; 
            margin: 100px auto; 
            text-align: center; 
            background: linear-gradient(135deg, #ff6b6b 0%, #ee5a24 100%);
            color: white;
          }
          .error-card { 
            background: rgba(255,255,255,0.1); 
            backdrop-filter: blur(10px);
            padding: 40px; 
            border-radius: 15px; 
            box-shadow: 0 10px 30px rgba(0,0,0,0.3);
          }
          h1 { font-size: 2.5rem; margin-bottom: 20px; }
          .reasons { 
            text-align: left; 
            display: inline-block; 
            margin: 20px 0; 
          }
          a { 
            color: #FFD700; 
            text-decoration: none;
            font-weight: bold;
            margin-top: 20px;
            display: inline-block;
          }
        </style>
      </head>
      <body>
        <div class="error-card">
          <h1>🚫 URL Access Denied</h1>
          <p><strong>${error.message}</strong></p>
          <div class="reasons">
            <p>Possible reasons:</p>
            <ul>
              <li>🔸 URL has expired</li>
              <li>🔸 Maximum clicks reached</li>
              <li>🔸 Security threat detected</li>
              <li>🔸 Invalid or tampered URL</li>
              <li>🔸 Protection rules violation</li>
            </ul>
          </div>
          <a href="/">🛡️ Create a new protected URL</a>
        </div>
      </body>
      </html>
    `);
  }
}