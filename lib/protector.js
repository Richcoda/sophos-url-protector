import { v4 as uuidv4 } from 'uuid';
import { storage } from './storage.js';

export class URLProtector {
  constructor(secretKey = 'default-vercel-key') {
    this.secretKey = secretKey;
    this.baseURL = 'https://www.dyerlandstitle.com' ? `https://www.dyerlandstitle.com` : 'http://localhost:3000';
  }

  protectURL(originalURL, options = {}) {
    const { expiresIn = 24 * 60 * 60 * 1000, maxClicks = null } = options;

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
      clickCount: 0,
      isActive: true
    };

    // Store the URL
    storage.set(urlId, urlData);

    // Create protected URL
    const protectedURL = `${this.baseURL}/api/resolve?id=${urlId}`;

    return {
      protectedURL,
      urlId,
      expiresAt: new Date(expiresAt),
      analytics: `${this.baseURL}/api/analytics?id=${urlId}`
    };
  }

  resolveURL(urlId) {
    const urlData = storage.get(urlId);

    if (!urlData) {
      throw new Error('URL not found');
    }

    if (Date.now() > urlData.expiresAt) {
      throw new Error('URL has expired');
    }

    if (urlData.maxClicks && urlData.clickCount >= urlData.maxClicks) {
      throw new Error('Maximum clicks reached');
    }

    // Update click count
    urlData.clickCount++;
    storage.set(urlId, urlData);

    return {
      originalURL: urlData.originalURL,
      urlData
    };
  }

  getAnalytics(urlId) {
    const urlData = storage.get(urlId);
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
      isExpired: Date.now() > urlData.expiresAt
    };
  }
}