import CryptoJS from 'crypto-js';
import { v4 as uuidv4 } from 'uuid';
import base64url from 'base64url';

// Global in-memory storage (shared across imports in same process)
const globalURLStorage = new Map();

export class SophosURLProtector {
  constructor(secretKey, domain = 'sophos-protector.com') {
    this.secretKey = secretKey;
    this.domain = domain;
    this.baseURL = process.env.VERCEL_URL ? `https://${process.env.VERCEL_URL}` : 'http://localhost:3000';
    this.storage = globalURLStorage; // Use global storage
  }

  protectURL(originalURL, options = {}) {
    // ... existing code ...
    
    // Store in global storage
    this.storage.set(urlId, urlData);
    console.log('💾 Stored in global storage. Total URLs:', this.storage.size);
    
    // ... rest of method ...
  }

  async resolveProtectedURL(sophosParams) {
    try {
      // ... existing code ...
      
      const urlId = base64url.decode(i);
      console.log('🔍 Looking up URL with ID:', urlId);
      console.log('📊 Global storage size:', this.storage.size);

      // Get from global storage
      const storedData = this.storage.get(urlId);
      
      if (!storedData) {
        console.log('❌ URL not found in global storage');
        throw new Error('URL not found');
      }

      // ... rest of method ...
    } catch (error) {
      throw new Error(`URL resolution failed: ${error.message}`);
    }
  }

  // ... rest of methods ...
}