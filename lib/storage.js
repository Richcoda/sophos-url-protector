import fs from 'fs';
import path from 'path';

const STORAGE_FILE = './url-storage.json';

// Initialize storage file if it doesn't exist
if (!fs.existsSync(STORAGE_FILE)) {
  fs.writeFileSync(STORAGE_FILE, JSON.stringify({}));
}

export class URLStorage {
  constructor() {
    this.load();
  }

  load() {
    try {
      const data = fs.readFileSync(STORAGE_FILE, 'utf8');
      this.storage = JSON.parse(data);
    } catch (error) {
      console.log('❌ Error loading storage, initializing empty:', error.message);
      this.storage = {};
    }
  }

  save() {
    try {
      fs.writeFileSync(STORAGE_FILE, JSON.stringify(this.storage, null, 2));
    } catch (error) {
      console.log('❌ Error saving storage:', error.message);
    }
  }

  set(key, value) {
    this.storage[key] = value;
    this.save();
    return true;
  }

  get(key) {
    return this.storage[key] || null;
  }

  has(key) {
    return key in this.storage;
  }

  delete(key) {
    if (this.has(key)) {
      delete this.storage[key];
      this.save();
      return true;
    }
    return false;
  }

  getAll() {
    return { ...this.storage };
  }

  clear() {
    this.storage = {};
    this.save();
  }
}

// Create singleton instance
export const urlStorage = new URLStorage();