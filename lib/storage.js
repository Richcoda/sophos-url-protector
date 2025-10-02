// Vercel-compatible storage (in-memory only)
class VercelStorage {
  constructor() {
    this.storage = new Map();
    console.log('🔄 Using Vercel-compatible in-memory storage');
  }

  set(key, value) {
    this.storage.set(key, value);
    console.log(`💾 Stored key: ${key}`);
    return true;
  }

  get(key) {
    const value = this.storage.get(key);
    console.log(`🔍 Retrieved key: ${key}, found: ${!!value}`);
    return value || null;
  }

  has(key) {
    return this.storage.has(key);
  }

  delete(key) {
    return this.storage.delete(key);
  }

  getAll() {
    const result = {};
    this.storage.forEach((value, key) => {
      result[key] = value;
    });
    return result;
  }

  clear() {
    this.storage.clear();
  }

  get size() {
    return this.storage.size;
  }
}

export const urlStorage = new VercelStorage();