import CryptoJS from 'crypto-js';
import { v4 as uuidv4 } from 'uuid';
import base64url from 'base64url';

const urlStorage = new Map();

export class SophosURLProtector {
  constructor(secretKey, domain = 'sophos-protector.com') {
    this.secretKey = secretKey;
    this.domain = domain; // Use provided domain
    this.baseURL = process.env.VERCEL_URL ? `https://${process.env.VERCEL_URL}` : 'http://localhost:3000';
  }

  protectURL(originalURL, options = {}) {
    const {
      expiresIn = 720 * 60 * 60 * 1000,
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

    // Simple encryption for testing
    const encryptedData = this.simpleEncrypt(JSON.stringify(urlData));
    
    // Generate security components
    const securityToken = this.generateSecurityToken(urlId, timestamp);
    const verificationHash = this.generateVerificationHash(encryptedData, securityToken);
    const sophosSignature = this.generateSophosSignature(encryptedData, securityToken);

    // Store URL data
    urlStorage.set(urlId, urlData);

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

  // Simplified encryption for testing
  simpleEncrypt(data) {
    return CryptoJS.AES.encrypt(data, this.secretKey).toString();
  }

  simpleDecrypt(encryptedData) {
    const bytes = CryptoJS.AES.decrypt(encryptedData, this.secretKey);
    return bytes.toString(CryptoJS.enc.Utf8);
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

  generateSecurityToken(urlId, timestamp) {
    const tokenData = { id: urlId, timestamp };
    return CryptoJS.AES.encrypt(JSON.stringify(tokenData), this.secretKey + timestamp).toString();
  }

  generateVerificationHash(encryptedData, securityToken) {
    const dataToHash = encryptedData + securityToken + this.secretKey;
    return CryptoJS.SHA256(dataToHash).toString(CryptoJS.enc.Hex);
  }

  generateSophosSignature(encryptedData, securityToken) {
    const signaturePayload = {
      version: "SOPHOTOCENCRYPTION",
      timestamp: Date.now(),
      data: encryptedData,
      token: securityToken
    };
    const signatureString = JSON.stringify(signaturePayload);
    const encryptedSignature = CryptoJS.AES.encrypt(signatureString, this.secretKey + 'signature').toString();
    return base64url.encode(encryptedSignature);
  }

  async resolveProtectedURL(sophosParams) {
    try {
      const { d, u, p, i, t, h, s } = sophosParams;

      // Basic validation
      if (d !== this.domain) throw new Error('Invalid protection domain');

      // Decode parameters
      const urlId = base64url.decode(i);
      const encryptedData = base64url.decode(u);
      const securityToken = base64url.decode(t);

      // Decrypt URL data
      const decryptedData = this.simpleDecrypt(encryptedData);
      const urlData = JSON.parse(decryptedData);
      
      const storedData = urlStorage.get(urlData.id);
      if (!storedData) throw new Error('URL not found');

      // Update click count
      storedData.clickCount++;
      urlStorage.set(urlData.id, storedData);

      return {
        originalURL: storedData.originalURL,
        urlData: storedData
      };

    } catch (error) {
      throw new Error(`URL resolution failed: ${error.message}`);
    }
  }

  getURLAnalytics(urlId) {
    const urlData = urlStorage.get(urlId);
    if (!urlData) throw new Error('URL not found');
    
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
}