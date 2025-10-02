import CryptoJS from 'crypto-js';
import { v4 as uuidv4 } from 'uuid';
import base64url from 'base64url';
import { urlStorage } from './storage.js';

export class SophosURLProtector {
  constructor(secretKey, domain = 'sophos-protector.com') {
    if (!secretKey) {
      throw new Error('Secret key is required');
    }
    this.secretKey = secretKey;
    this.domain = domain;
    this.baseURL = process.env.VERCEL_URL ? `https://${process.env.VERCEL_URL}` : 'http://localhost:3000';
  }

  protectURL(originalURL, options = {}) {
    const {
      expiresIn = 720 * 60 * 60 * 1000, // 30 days default
      maxClicks = null,
      protectionMode = 'm'
    } = options;

    // Validate URL
    try {
      new URL(originalURL);
    } catch (error) {
      throw new Error('Invalid URL format');
    }

    const urlId = uuidv4();
    const timestamp = Date.now();
    const expiresAt = timestamp + expiresIn;

    const urlData = {
      id: urlId,
      originalURL,
      timestamp,
      expiresAt,
      maxClicks,
      protectionMode,
      clickCount: 0,
      isActive: true
    };

    // Store in persistent storage
    urlStorage.set(urlId, urlData);

    // Encrypt the URL data
    const encryptedData = this.encryptData(JSON.stringify(urlData));
    
    // Generate security components
    const securityToken = this.generateSecurityToken(urlId, timestamp);
    const verificationHash = this.generateVerificationHash(encryptedData, securityToken);
    const sophosSignature = this.generateSophosSignature(encryptedData, securityToken);

    // Construct Sophos-style URL
    const protectedURL = this.constructSophosURL({
      domain: this.domain,
      encryptedData,
      protectionMode,
      urlId,
      securityToken,
      verificationHash,
      sophosSignature
    });

    return {
      protectedURL,
      urlId,
      expiresAt: new Date(expiresAt),
      protectionMode,
      analytics: `${this.baseURL}/api/analytics?id=${urlId}`
    };
  }

  async resolveProtectedURL(sophosParams) {
    try {
      const { d, u, p, i, t, h, s } = sophosParams;

      // Validate domain
      if (d !== this.domain) {
        throw new Error('Invalid protection domain');
      }

      // Validate protection mode
      if (!['l', 'm', 'h'].includes(p)) {
        throw new Error('Invalid protection mode');
      }

      // Verify Sophos signature
      if (!this.verifySophosSignature(s, u, t)) {
        throw new Error('Invalid security signature');
      }

      // Verify hash
      if (!this.validateRequest(u, t, h)) {
        throw new Error('Invalid verification hash');
      }

      // Decode parameters
      const urlId = base64url.decode(i);
      const encryptedData = base64url.decode(u);
      const securityToken = base64url.decode(t);

      // Get from storage
      const storedData = urlStorage.get(urlId);
      
      if (!storedData) {
        throw new Error('URL not found');
      }

      // Validate URL data
      if (Date.now() > storedData.expiresAt) {
        throw new Error('URL has expired');
      }

      if (!storedData.isActive) {
        throw new Error('URL is no longer active');
      }

      if (storedData.maxClicks && storedData.clickCount >= storedData.maxClicks) {
        throw new Error('Maximum clicks reached');
      }

      // Security check
      const securityCheck = await this.performSecurityChecks(storedData.originalURL);
      if (!securityCheck.isSafe) {
        throw new Error(`Security threat detected: ${securityCheck.threats.join(', ')}`);
      }

      // Update click count
      storedData.clickCount++;
      urlStorage.set(urlId, storedData);

      return {
        originalURL: storedData.originalURL,
        urlData: storedData,
        securityCheck
      };

    } catch (error) {
      throw new Error(`URL resolution failed: ${error.message}`);
    }
  }

  // Encryption methods
  encryptData(data) {
    return CryptoJS.AES.encrypt(data, this.secretKey).toString();
  }

  decryptData(encryptedData) {
    const bytes = CryptoJS.AES.decrypt(encryptedData, this.secretKey);
    return bytes.toString(CryptoJS.enc.Utf8);
  }

  generateSecurityToken(urlId, timestamp) {
    const tokenData = {
      id: urlId,
      timestamp,
      salt: CryptoJS.lib.WordArray.random(16).toString()
    };
    
    return CryptoJS.AES.encrypt(
      JSON.stringify(tokenData), 
      this.secretKey + timestamp
    ).toString();
  }

  generateVerificationHash(encryptedData, securityToken) {
    const dataToHash = encryptedData + securityToken + this.secretKey;
    return CryptoJS.SHA256(dataToHash).toString(CryptoJS.enc.Hex);
  }

  validateRequest(encryptedData, securityToken, verificationHash) {
    const expectedHash = this.generateVerificationHash(encryptedData, securityToken);
    return expectedHash === verificationHash;
  }

  generateSophosSignature(encryptedData, securityToken) {
    const signaturePayload = {
      version: "SOPHOTOCENCRYPTION",
      timestamp: Date.now(),
      data: encryptedData,
      token: securityToken,
      salt: CryptoJS.lib.WordArray.random(16).toString()
    };

    const signatureString = JSON.stringify(signaturePayload);
    const encryptedSignature = CryptoJS.AES.encrypt(signatureString, this.secretKey + 'signature').toString();
    return base64url.encode(encryptedSignature);
  }

  verifySophosSignature(signature, encryptedData, securityToken) {
    try {
      const decodedSig = base64url.decode(signature);
      const decryptedSig = CryptoJS.AES.decrypt(decodedSig, this.secretKey + 'signature').toString(CryptoJS.enc.Utf8);
      const sigData = JSON.parse(decryptedSig);

      return sigData.version === "SOPHOTOCENCRYPTION" &&
             sigData.data === encryptedData &&
             sigData.token === securityToken &&
             (Date.now() - sigData.timestamp) < (5 * 60 * 1000); // 5 minute validity
    } catch (error) {
      return false;
    }
  }

  constructSophosURL(params) {
    const queryParams = new URLSearchParams({
      d: params.domain,
      u: base64url.encode(params.encryptedData),
      p: params.protectionMode,
      i: base64url.encode(params.urlId),
      t: base64url.encode(params.securityToken),
      h: params.verificationHash,
      s: params.sophosSignature
    });

    return `${this.baseURL}/api/resolve?${queryParams.toString()}`;
  }

  async performSecurityChecks(url) {
    const threats = [];
    
    // Basic security checks
    if (this.isSuspiciousURL(url)) {
      threats.push('Suspicious URL pattern detected');
    }
    
    return {
      isSafe: threats.length === 0,
      threats
    };
  }

  isSuspiciousURL(url) {
    const suspiciousPatterns = [
      /\.(exe|bat|cmd|msi|dmg|jar)$/i,
      /javascript:/i,
      /data:text\/html/i,
      /vbscript:/i
    ];
    
    return suspiciousPatterns.some(pattern => pattern.test(url));
  }

  getURLAnalytics(urlId) {
    const urlData = urlStorage.get(urlId);
    if (!urlData) {
      throw new Error('URL not found');
    }
    
    return {
      id: urlData.id,
      originalURL: urlData.originalURL,
      created: new Date(urlData.timestamp),
      expires: new Date(urlData.expiresAt),
      clicks: urlData.clickCount,
      maxClicks: urlData.maxClicks,
      isActive: urlData.isActive,
      isExpired: Date.now() > urlData.expiresAt,
      protectionMode: urlData.protectionMode
    };
  }

  deactivateURL(urlId) {
    const urlData = urlStorage.get(urlId);
    if (urlData) {
      urlData.isActive = false;
      urlStorage.set(urlId, urlData);
      return true;
    }
    return false;
  }
}