// Vercel-compatible persistent storage using global object
class VercelStorage {
    constructor() {
      if (!global.urlProtectorStorage) {
        global.urlProtectorStorage = new Map();
      }
      this.storage = global.urlProtectorStorage;
    }
  
    set(key, value) {
      this.storage.set(key, value);
      return true;
    }
  
    get(key) {
      return this.storage.get(key);
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