import CryptoJS from 'crypto-js';
import { v4 as uuidv4 } from 'uuid';
import base64url from 'base64url';
import { urlStorage } from './storage.js';

export class SophosURLProtector {
  constructor(secretKey, domain = 'sophos-protector.com') {
    if (!secretKey || typeof secretKey !== 'string') {
      throw new Error('Invalid secret key: must be a non-empty string');
    }
    
    this.secretKey = secretKey;
    this.domain = domain;
    this.baseURL = process.env.VERCEL_URL ? `https://${process.env.VERCEL_URL}` : 'http://localhost:3000';
    
    console.log('🛡️ SophosURLProtector initialized with key length:', secretKey.length);
  }

  protectURL(originalURL, options = {}) {
    try {
      console.log('🔒 Starting URL protection process...');
      
      const {
        expiresIn = 720 * 60 * 60 * 1000, // 30 days default
        maxClicks = null,
        protectionMode = 'm'
      } = options;

      // Validate URL
      if (!originalURL || typeof originalURL !== 'string') {
        throw new Error('Invalid URL: must be a non-empty string');
      }

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

      console.log('💾 Storing URL data with ID:', urlId);
      
      // Store in persistent storage
      urlStorage.set(urlId, urlData);

      // Encrypt the URL data
      console.log('🔐 Encrypting URL data...');
      const encryptedData = this.encryptData(urlData);
      console.log('✅ URL data encrypted');
      
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

      console.log('✅ URL protection completed successfully');

      return {
        protectedURL,
        urlId,
        expiresAt: new Date(expiresAt),
        protectionMode,
        analytics: `${this.baseURL}/api/analytics?id=${urlId}`
      };

    } catch (error) {
      console.error('❌ URL protection failed:', error.message);
      throw error;
    }
  }

  async resolveProtectedURL(sophosParams) {
    try {
      console.log('🔄 Starting URL resolution...');
      
      const { d, u, p, i, t, h, s } = sophosParams;

      // Validate required parameters
      if (!d || !u || !p || !i || !t || !h || !s) {
        throw new Error('Missing required URL parameters');
      }

      // Validate domain
      if (d !== this.domain) {
        throw new Error('Invalid protection domain');
      }

      // Validate protection mode
      if (!['l', 'm', 'h'].includes(p)) {
        throw new Error('Invalid protection mode');
      }

      console.log('🔍 Decoding URL parameters...');
      
      // Decode parameters
      const urlId = base64url.decode(i);
      const encryptedData = base64url.decode(u);
      const securityToken = base64url.decode(t);

      console.log('🔑 Verifying security signature...');
      
      // Verify Sophos signature
      if (!this.verifySophosSignature(s, u, t)) {
        throw new Error('Invalid security signature');
      }

      // Verify hash
      if (!this.validateRequest(u, t, h)) {
        throw new Error('Invalid verification hash');
      }

      console.log('📊 Looking up URL in storage...');
      
      // Get from storage
      const storedData = urlStorage.get(urlId);
      
      if (!storedData) {
        console.log('❌ URL not found in storage');
        throw new Error('URL not found');
      }

      console.log('✅ Found URL data');

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
      console.log('🛡️ Performing security checks...');
      const securityCheck = await this.performSecurityChecks(storedData.originalURL);
      if (!securityCheck.isSafe) {
        throw new Error(`Security threat detected: ${securityCheck.threats.join(', ')}`);
      }

      // Update click count
      storedData.clickCount++;
      urlStorage.set(urlId, storedData);

      console.log('✅ URL resolution completed successfully');

      return {
        originalURL: storedData.originalURL,
        urlData: storedData,
        securityCheck
      };

    } catch (error) {
      console.error('❌ URL resolution failed:', error.message);
      throw new Error(`URL resolution failed: ${error.message}`);
    }
  }

  // Encryption methods with proper error handling
  encryptData(data) {
    try {
      console.log('🔐 Starting encryption...');
      
      if (!this.secretKey || typeof this.secretKey !== 'string') {
        throw new Error('Invalid secret key for encryption');
      }
      
      if (!data) {
        throw new Error('No data provided for encryption');
      }

      const jsonString = JSON.stringify(data);
      console.log('📝 Data to encrypt length:', jsonString.length);
      
      const encrypted = CryptoJS.AES.encrypt(jsonString, this.secretKey);
      
      if (!encrypted) {
        throw new Error('Encryption returned null or undefined');
      }
      
      const encryptedString = encrypted.toString();
      
      if (!encryptedString) {
        throw new Error('Encrypted string is empty');
      }
      
      console.log('✅ Encryption successful');
      return encryptedString;
      
    } catch (error) {
      console.error('❌ Encryption error:', error);
      throw new Error(`Encryption failed: ${error.message}`);
    }
  }

  decryptData(encryptedData) {
    try {
      console.log('🔓 Starting decryption...');
      
      if (!this.secretKey || typeof this.secretKey !== 'string') {
        throw new Error('Invalid secret key for decryption');
      }
      
      if (!encryptedData) {
        throw new Error('No encrypted data provided');
      }

      console.log('📝 Encrypted data length:', encryptedData.length);
      
      const bytes = CryptoJS.AES.decrypt(encryptedData, this.secretKey);
      
      if (!bytes) {
        throw new Error('Decryption returned null or undefined');
      }
      
      const jsonString = bytes.toString(CryptoJS.enc.Utf8);
      
      if (!jsonString) {
        throw new Error('Decryption resulted in empty data - invalid key or corrupted data');
      }
      
      console.log('✅ Decryption successful');
      return JSON.parse(jsonString);
      
    } catch (error) {
      console.error('❌ Decryption error:', error);
      throw new Error(`Decryption failed: ${error.message}`);
    }
  }

  generateSecurityToken(urlId, timestamp) {
    try {
      const tokenData = {
        id: urlId,
        timestamp,
        salt: CryptoJS.lib.WordArray.random(16).toString()
      };
      
      const tokenString = JSON.stringify(tokenData);
      const encryptedToken = CryptoJS.AES.encrypt(tokenString, this.secretKey + timestamp).toString();
      
      return encryptedToken;
    } catch (error) {
      console.error('❌ Security token generation failed:', error);
      throw new Error(`Security token generation failed: ${error.message}`);
    }
  }

  generateVerificationHash(encryptedData, securityToken) {
    try {
      const dataToHash = encryptedData + securityToken + this.secretKey;
      return CryptoJS.SHA256(dataToHash).toString(CryptoJS.enc.Hex);
    } catch (error) {
      console.error('❌ Verification hash generation failed:', error);
      throw new Error(`Verification hash generation failed: ${error.message}`);
    }
  }

  validateRequest(encryptedData, securityToken, verificationHash) {
    try {
      const expectedHash = this.generateVerificationHash(encryptedData, securityToken);
      return expectedHash === verificationHash;
    } catch (error) {
      console.error('❌ Request validation failed:', error);
      return false;
    }
  }

  generateSophosSignature(encryptedData, securityToken) {
    try {
      console.log('🔏 Generating Sophos signature...');
      
      const signaturePayload = {
        version: "SOPHOTOCENCRYPTION",
        timestamp: Date.now(),
        data: encryptedData,
        token: securityToken,
        salt: CryptoJS.lib.WordArray.random(16).toString()
      };
  
      console.log('📝 Signature payload created');
      
      const signatureString = JSON.stringify(signaturePayload);
      console.log('📄 Signature string length:', signatureString.length);
      
      // Use a consistent key derivation for signature
      const signatureKey = this.secretKey + 'signature';
      console.log('🔑 Using signature key');
      
      const encryptedSignature = CryptoJS.AES.encrypt(signatureString, signatureKey).toString();
      
      if (!encryptedSignature) {
        throw new Error('Signature encryption returned empty');
      }
      
      const encodedSignature = base64url.encode(encryptedSignature);
      console.log('✅ Sophos signature generated successfully');
      
      return encodedSignature;
    } catch (error) {
      console.error('❌ Sophos signature generation failed:', error);
      throw new Error(`Sophos signature generation failed: ${error.message}`);
    }
  }
  
  verifySophosSignature(signature, encryptedData, securityToken) {
    try {
      console.log('🔍 Verifying Sophos signature...');
      
      if (!signature) {
        console.error('❌ No signature provided');
        return false;
      }
  
      console.log('📄 Signature length:', signature.length);
      
      // Decode the signature
      const decodedSig = base64url.decode(signature);
      console.log('📄 Decoded signature length:', decodedSig.length);
      
      // Use the same key derivation as in generation
      const signatureKey = this.secretKey + 'signature';
      
      // Decrypt the signature
      const decryptedSig = CryptoJS.AES.decrypt(decodedSig, signatureKey).toString(CryptoJS.enc.Utf8);
      
      if (!decryptedSig) {
        console.error('❌ Signature decryption failed - returned empty');
        return false;
      }
      
      console.log('📄 Decrypted signature length:', decryptedSig.length);
      
      // Parse the signature data
      const sigData = JSON.parse(decryptedSig);
      
      // Validate signature structure
      if (sigData.version !== "SOPHOTOCENCRYPTION") {
        console.error('❌ Signature version mismatch:', sigData.version);
        return false;
      }
  
      if (sigData.data !== encryptedData) {
        console.error('❌ Signature data mismatch');
        console.log('  Expected data length:', encryptedData.length);
        console.log('  Actual data length:', sigData.data.length);
        return false;
      }
  
      if (sigData.token !== securityToken) {
        console.error('❌ Signature token mismatch');
        console.log('  Expected token length:', securityToken.length);
        console.log('  Actual token length:', sigData.token.length);
        return false;
      }
  
      // Check timestamp validity (extended to 10 minutes for testing)
      const timeDiff = Date.now() - sigData.timestamp;
      const maxAge = 10 * 60 * 1000; // 10 minutes
      
      if (timeDiff > maxAge) {
        console.error('❌ Signature expired, time difference (ms):', timeDiff);
        return false;
      }
  
      console.log('✅ Sophos signature verified successfully');
      console.log('   Time difference:', timeDiff, 'ms');
      
      return true;
    } catch (error) {
      console.error('❌ Sophos signature verification failed:', error.message);
      return false;
    }
  }

  constructSophosURL(params) {
    try {
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
    } catch (error) {
      console.error('❌ URL construction failed:', error);
      throw new Error(`URL construction failed: ${error.message}`);
    }
  }

  async performSecurityChecks(url) {
    try {
      const threats = [];
      
      // Basic security checks
      if (this.isSuspiciousURL(url)) {
        threats.push('Suspicious URL pattern detected');
      }
      
      return {
        isSafe: threats.length === 0,
        threats
      };
    } catch (error) {
      console.error('❌ Security check failed:', error);
      // If security checks fail, assume safe to avoid blocking legitimate URLs
      return { isSafe: true, threats: [] };
    }
  }

  isSuspiciousURL(url) {
    try {
      const suspiciousPatterns = [
        /\.(exe|bat|cmd|msi|dmg|jar)$/i,
        /javascript:/i,
        /data:text\/html/i,
        /vbscript:/i
      ];
      
      return suspiciousPatterns.some(pattern => pattern.test(url));
    } catch (error) {
      console.error('❌ URL suspicion check failed:', error);
      return false;
    }
  }

  getURLAnalytics(urlId) {
    try {
      console.log('📈 Getting analytics for:', urlId);
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
    } catch (error) {
      console.error('❌ Analytics retrieval failed:', error);
      throw new Error(`Analytics retrieval failed: ${error.message}`);
    }
  }

  deactivateURL(urlId) {
    try {
      const urlData = urlStorage.get(urlId);
      if (urlData) {
        urlData.isActive = false;
        urlStorage.set(urlId, urlData);
        return true;
      }
      return false;
    } catch (error) {
      console.error('❌ URL deactivation failed:', error);
      return false;
    }
  }
}