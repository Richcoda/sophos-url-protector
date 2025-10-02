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
  if (req.method !== 'GET') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const { d, u, p, i, t, h, s } = req.query;
    
    // Validate required parameters
    if (!d || !u || !p || !i || !t || !h || !s) {
      return res.status(400).send(`
        <!DOCTYPE html>
        <html>
        <head>
          <title>Sophos URL Protector - Error</title>
          <meta charset="utf-8">
          <meta name="viewport" content="width=device-width, initial-scale=1">
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
            a { 
              display: inline-block;
              background: #007bff;
              color: white;
              padding: 12px 30px;
              border-radius: 8px;
              text-decoration: none;
              font-weight: 600;
              transition: background 0.3s;
            }
            a:hover {
              background: #0056b3;
            }
          </style>
        </head>
        <body>
          <div class="error-card">
            <h1>🔒 Invalid Protected URL</h1>
            <p>The URL is missing required security parameters or has been tampered with.</p>
            <a href="/">🛡️ Create New Protected URL</a>
          </div>
        </body>
        </html>
      `);
    }

    const protector = new SophosURLProtector(getSecretKey());

    const result = await protector.resolveProtectedURL({
      d, u, p, i, t, h, s
    });

    // Redirect to the original URL
    res.redirect(302, result.originalURL);

  } catch (error) {
    console.error('Resolution error:', error.message);
    
    res.status(400).send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>Sophos URL Protector - Access Denied</title>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
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
          a { 
            display: inline-block;
            background: #28a745;
            color: white;
            padding: 12px 30px;
            border-radius: 8px;
            text-decoration: none;
            font-weight: 600;
            transition: background 0.3s;
          }
          a:hover {
            background: #218838;
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
          <a href="/">🛡️ Create New Protected URL</a>
        </div>
      </body>
      </html>
    `);
  }
}